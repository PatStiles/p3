package edu.wisc.cs.sdn.vnet.rt;

import java.nio.ByteBuffer;
import java.util.Iterator;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;

import net.floodlightcontroller.packet.Data;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.ICMP;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.MACAddress;
import net.floodlightcontroller.packet.UDP;
import net.floodlightcontroller.packet.RIPv2;
import net.floodlightcontroller.packet.RIPv2Entry;

/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device
{	
	/** Routing table for the router */
	private RouteTable routeTable;

	/** ARP cache for the router */
	private ArpCache arpCache;

	/** Destination addresses for RIP requests and unsolicited responses */
	private static final int RIP_IP_ADDRESS = IPv4.toIPv4Address("224.0.0.9");
	private static final MACAddress RIP_MAC_ADDRESS = MACAddress.valueOf("FF:FF:FF:FF:FF:FF");
	private static final int EMPTY_GATEWAY_ADDRESS = IPv4.toIPv4Address("0.0.0.0");

	private class timeOutChecker extends Thread {
		public void run() {
			Iterator<RouteEntry> iter = routeTable.getEntries().iterator();
			while(true) {
				if(timeOutChecker.interrupted())
				{ break; }

				while (iter.hasNext()) {
					RouteEntry t = iter.next();
					if(t == null)
					{ continue; }
					if ((System.currentTimeMillis() - t.getTimeUpdated()) >= 30000) {
						iter.remove();
					}
				}
			}
		}
	}
	/**
	 * Creates a router for a specific host.
	 * @param host hostname for the router
	 */
	public Router(String host, DumpFile logfile)
	{
		super(host,logfile);
		this.routeTable = new RouteTable();
		this.arpCache = new ArpCache();
		
		//start timeout thread`
		(new timeOutChecker()).start();
	}

	/**
	 * @return routing table for the router
	 */
	public RouteTable getRouteTable()
	{ return this.routeTable; }

	/**
	 * Load a new routing table from a file.
	 * @param routeTableFile the name of the file containing the routing table
	 */
	public void loadRouteTable(String routeTableFile)
	{
		if (!routeTable.load(routeTableFile, this))
		{
			System.err.println("Error setting up routing table from file "
					+ routeTableFile);
			System.exit(1);
		}

		System.out.println("Loaded static route table");
		System.out.println("-------------------------------------------------");
		System.out.print(this.routeTable.toString());
		System.out.println("-------------------------------------------------");
	}

	/**
	 * Load a new ARP cache from a file.
	 * @param arpCacheFile the name of the file containing the ARP cache
	 */
	public void loadArpCache(String arpCacheFile)
	{
		if (!arpCache.load(arpCacheFile))
		{
			System.err.println("Error setting up ARP cache from file "
					+ arpCacheFile);
			System.exit(1);
		}

		System.out.println("Loaded static ARP cache");
		System.out.println("----------------------------------");
		System.out.print(this.arpCache.toString());
		System.out.println("----------------------------------");
	}

	/**
	 * Handle an Ethernet packet received on a specific interface.
	 * @param etherPacket the Ethernet packet that was received
	 * @param inIface the interface on which the packet was received
	 */
	public void handlePacket(Ethernet etherPacket, Iface inIface)
	{
		System.out.println("*** -> Received packet: " +
				etherPacket.toString().replace("\n", "\n\t"));

		/********************************************************************/
		/* TODO: Handle packets                                             */

		// TODO: Handle RIP packets, error casting payload to IPv4 (move this somewhere else)
		//IPv4 ipPacket = (IPv4)etherPacket.getPayload();
		//if (ipPacket.getProtocol() == IPv4.PROTOCOL_UDP && ipPacket.getSourceAddress() == UDP.RIP_PORT && ipPacket.getDestinationAddress() == UDP.RIP_PORT) 
		//{
		//	handleRipPacket(etherPacket, inIface);
		//}

		switch(etherPacket.getEtherType())
		{
		case Ethernet.TYPE_IPv4:
			this.handleIpPacket(etherPacket, inIface);
			break;
		// Ignore all other packet types, for now
		}

		/********************************************************************/
	}

	private void handleIpPacket(Ethernet etherPacket, Iface inIface)
	{
		// Make sure it's an IP packet
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4)
		{ return; }

		// Get IP header
		IPv4 ipPacket = (IPv4)etherPacket.getPayload();
		System.out.println("Handle IP packet");

		// Verify checksum
		short origCksum = ipPacket.getChecksum();
		ipPacket.resetChecksum();
		byte[] serialized = ipPacket.serialize();
		ipPacket.deserialize(serialized, 0, serialized.length);
		short calcCksum = ipPacket.getChecksum();
		if (origCksum != calcCksum)
		{ return; }

		// Check TTL
		ipPacket.setTtl((byte)(ipPacket.getTtl()-1));
		if (0 == ipPacket.getTtl())
		{ 
			Ethernet icmpMsg = genICMPMsg((byte) 11, (byte) 0,etherPacket, inIface);
			this.sendPacket(icmpMsg, inIface);
			return; 
		}

		// Reset checksum now that TTL is decremented
		ipPacket.resetChecksum();

		// Check if packet is destined for one of router's interfaces
		for (Iface iface : this.interfaces.values())
		{
			if (ipPacket.getDestinationAddress() == iface.getIpAddress())
			{ 
				if(ipPacket.getProtocol() == IPv4.PROTOCOL_UDP || ipPacket.getProtocol() == IPv4.PROTOCOL_TCP)
				{

					Ethernet icmpMsg = genICMPMsg((byte) 3, (byte) 3,etherPacket, inIface);
					this.sendPacket(icmpMsg, iface);
					return; 
				}

				if(ipPacket.getProtocol() == IPv4.PROTOCOL_ICMP)
				{
					Ethernet icmpMsg = genEchoMsg((byte) 0, (byte) 0,etherPacket, inIface);
					this.sendPacket(icmpMsg, iface);
					return; 
					
				}
				return; 
			}
		}

		// Do route lookup and forward
		this.forwardIpPacket(etherPacket, inIface);
	}

	private void forwardIpPacket(Ethernet etherPacket, Iface inIface)
	{
		// Make sure it's an IP packet
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4)
		{ return; }
		System.out.println("Forward IP packet");

		// Get IP header
		IPv4 ipPacket = (IPv4)etherPacket.getPayload();
		int dstAddr = ipPacket.getDestinationAddress();

		// Find matching route table entry 
		RouteEntry bestMatch = this.routeTable.lookup(dstAddr);

		// If no entry matched, do nothing
		if (null == bestMatch)
		{ 
			Ethernet icmpMsg = genICMPMsg((byte) 3, (byte) 0, etherPacket, inIface);

			if (icmpMsg != null)
			{ this.sendPacket(icmpMsg, inIface); }

			return; 
		}

		// Make sure we don't sent a packet back out the interface it came in
		Iface outIface = bestMatch.getInterface();
		if (outIface == inIface)
		{ return; }

		// Set source MAC address in Ethernet header
		etherPacket.setSourceMACAddress(outIface.getMacAddress().toBytes());

		// If no gateway, then nextHop is IP destination
		int nextHop = bestMatch.getGatewayAddress();
		if (0 == nextHop)
		{ nextHop = dstAddr; }

		// Set destination MAC address in Ethernet header
		ArpEntry arpEntry = this.arpCache.lookup(nextHop);
		if (null == arpEntry)
		{ 	
			Ethernet icmpMsg = genICMPMsg((byte) 3, (byte) 1, etherPacket, inIface);
			this.sendPacket(icmpMsg, outIface);
			return; 
		}

		etherPacket.setDestinationMACAddress(arpEntry.getMac().toBytes());

		this.sendPacket(etherPacket, outIface);
	}

	private Ethernet genICMPMsg(byte icmpType, byte icmpCode, Ethernet etherPacket, Iface inIface)
	{
		Ethernet ether = new Ethernet();
		ether.setEtherType(Ethernet.TYPE_IPv4);

		//get ipv4 packet info
		IPv4 ipPacket = (IPv4)etherPacket.getPayload();
		int dstAddr = ipPacket.getSourceAddress();

		// Find matching route table entry 
		RouteEntry bestMatch = this.routeTable.lookup(dstAddr);
		if (null == bestMatch)
		{ return null; }

		Iface outIface = bestMatch.getInterface();
		ether.setSourceMACAddress(outIface.getMacAddress().toBytes());

		// If no gateway, then nextHop is IP destination
		int nextHop = bestMatch.getGatewayAddress();
		if (0 == nextHop)
		{ nextHop = dstAddr; }

		// Set destination MAC address in Ethernet header
		ArpEntry arpEntry = this.arpCache.lookup(nextHop);
		if (arpEntry == null)
		{ return null; }
		ether.setDestinationMACAddress(arpEntry.getMac().toBytes());

		//Set IP Header Values
		IPv4 ip = new IPv4();
		ip.setTtl((byte)64);
		ip.setProtocol(IPv4.PROTOCOL_ICMP);
		ip.setSourceAddress(inIface.getIpAddress());
		ip.setDestinationAddress(ipPacket.getSourceAddress());

		//Set ICMP Header Values
		ICMP icmp = new ICMP();
		icmp.setIcmpType(icmpType);
		icmp.setIcmpCode(icmpCode);

		//Set Data for ICMP Header
		//If cast of getHeaderLength() is invalid try Byte.toUnsignedInt
		ByteBuffer bbuf = ByteBuffer.allocate(4 + ((int)ipPacket.getHeaderLength() * 4) + 8);
		byte[] header = ipPacket.serialize();
		bbuf.putInt(0);
		bbuf.put(header, 0, (((int)ipPacket.getHeaderLength() * 4) + 8));
		Data data = new Data(bbuf.array());

		//Set Payloads
		icmp.setPayload(data);	
		ip.setPayload(icmp);
		ether.setPayload(ip);
		return ether;
	}

	private Ethernet genEchoMsg(byte icmpType, byte icmpCode, Ethernet etherPacket, Iface inIface)
	{
		Ethernet ether = new Ethernet();
		ether.setEtherType(Ethernet.TYPE_IPv4);

		//get ipv4 packet info
		IPv4 ipPacket = (IPv4)etherPacket.getPayload();
		int dstAddr = ipPacket.getDestinationAddress();

		// Find matching route table entry 
		RouteEntry bestMatch = this.routeTable.lookup(dstAddr);
		if (null == bestMatch)
		{ return null; }

		// Make sure we don't sent a packet back out the interface it came in
		Iface outIface = bestMatch.getInterface();
		ether.setSourceMACAddress(outIface.getMacAddress().toBytes());

		// If no gateway, then nextHop is IP destination
		int nextHop = bestMatch.getGatewayAddress();
		if (0 == nextHop)
		{ nextHop = dstAddr; }

		// Set destination MAC address in Ethernet header
		ArpEntry arpEntry = this.arpCache.lookup(nextHop);
		ether.setDestinationMACAddress(arpEntry.getMac().toBytes());

		//Set IP Header Values
		IPv4 ip = new IPv4();
		ip.setTtl((byte)64);
		ip.setProtocol(IPv4.PROTOCOL_ICMP);
		ip.setSourceAddress(dstAddr);
		ip.setDestinationAddress(ipPacket.getSourceAddress());

		//Set ICMP Header Values
		ICMP icmp = new ICMP();
		icmp.setIcmpType(icmpType);
		icmp.setIcmpCode(icmpCode);

		//Set Payloads
		icmp.setPayload(((ICMP)ipPacket.getPayload()).getPayload());	
		ip.setPayload(icmp);
		ether.setPayload(ip);
		return ether;
	}

	private void handleRipPacket(Ethernet etherPacket, Iface inIface) 
	{
		// TODO: Update route table
		RIPv2 rip = (RIPv2)etherPacket.getPayload();

		for (RIPv2Entry entry : rip.getEntries())
		{
			int dstAddr = entry.getAddress();
			RouteEntry match = routeTable.lookup(dstAddr);

			// See 3.4.2 implementation in textbook
			if (match != null)
			{
				int curCost = match.getMetric();
				int newCost = entry.getMetric();

				if (newCost + 1 < curCost)
				{
					// TODO: found a better route
					match.setMetric(newCost + 1);
					match.setTimeSinceUpdate(0);
					break;
				}
				else if (entry.getNextHopAddress() == match.getDestinationAddress())
				{
					// TODO: metric for current next hop may have changed
					break;
				}
				else 
				{
					// Ignore this route
					return;
				}
			}
			else
			{
				// TODO: add new route to the table

			}
		}

		// TODO: Send RIP response packets
		// For sending requests and unsolicited responses (defined as static constants):
		//   Destination IP 		224.0.0.9
		//   Destination Ethernet	FF:FF:FF:FF:FF:FF
		// For sending response for specific request:
		//   Destination IP			inIface.getIpAddress()
		//   Destination Ethernet	inIface.getMacAddress()
		//
		//   To handle RIP routing use the algorithm in the slides of weeek 7 slide 12

		return;
	}

	public void rip() 
	{
		// Build initial table on startup
		this.buildRipRouteTable();

		// Send RIP request on all interfaces after initializing
		this.broadcastRip();

		//start thread that automatically sends out rip msgs every 10 secs.
	}

	private void buildRipRouteTable()
	{
		// Add RouteTable entries for directly reachable subnets
		for (Iface iface : this.interfaces.values())
		{
			int destinationAddress = iface.getIpAddress() & iface.getSubnetMask();
			int maskAddress = iface.getSubnetMask();

			this.routeTable.insert(destinationAddress, EMPTY_GATEWAY_ADDRESS, maskAddress, iface);
		}

		System.out.println("Loaded route table from directly reachable subnets");
		System.out.println("-------------------------------------------------");
		System.out.print(this.routeTable.toString());
		System.out.println("-------------------------------------------------");
	}

	private void broadcastRip()
	{
		for (Iface iface : this.interfaces.values())
		{
			Ethernet etherPacket = new Ethernet();
			etherPacket.setDestinationMACAddress(RIP_MAC_ADDRESS.toString());

			// TODO: use IP packet with UDP protocol instead ?
			UDP udpPacket = new UDP();
			udpPacket.setDestinationPort(UDP.RIP_PORT);

			RIPv2 rip = new RIPv2();
			rip.setCommand(RIPv2.COMMAND_REQUEST);

			for (RouteEntry tableEntry : routeTable.getEntries())
			{
				RIPv2Entry ripEntry = new RIPv2Entry();

				// TODO: set next hop address ?
				ripEntry.setAddress(tableEntry.getDestinationAddress());
				ripEntry.setSubnetMask(tableEntry.getMaskAddress());
				ripEntry.setMetric(tableEntry.getMetric());

				rip.addEntry(ripEntry);
			}
			
			udpPacket.setPayload(rip);
			etherPacket.setPayload(udpPacket);
			this.sendPacket(etherPacket, iface);
		}
	}
}
