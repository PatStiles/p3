package edu.wisc.cs.sdn.vnet.rt;

import java.nio.ByteBuffer;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;

import net.floodlightcontroller.packet.Data;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.ICMP;
import net.floodlightcontroller.packet.IPv4;

/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device
{	
	/** Routing table for the router */
	private RouteTable routeTable;

	/** ARP cache for the router */
	private ArpCache arpCache;

	/**
	 * Creates a router for a specific host.
	 * @param host hostname for the router
	 */
	public Router(String host, DumpFile logfile)
	{
		super(host,logfile);
		this.routeTable = new RouteTable();
		this.arpCache = new ArpCache();
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
			this.sendPacket(icmpMsg, inIface);
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
		ip.setSourceAddress(inIface.getIpAddress());
		ip.setDestinationAddress(ipPacket.getSourceAddress());

		//Set ICMP Header Values
		ICMP icmp = new ICMP();
		icmp.setIcmpType(icmpType);
		icmp.setIcmpCode(icmpCode);

		//Set Data for ICMP Header
		//If cast of getHeaderLength() is invalid try Byte.toUnsignedInt
		ByteBuffer bbuf = ByteBuffer.allocate(4 + (int)ipPacket.getHeaderLength() + 8);
		byte[] header = ipPacket.serialize();
		bbuf.put(header, 4, ((int)ipPacket.getHeaderLength() + 8));
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

		//Set Data for ICMP Header
		//If cast of getHeaderLength() is invalid try Byte.toUnsignedInt
		//This creates a ByteBuffer of the entire IPv4 message then slice it and removes the IPv4 header. Instructions weren't that clear on what ethe spec is???
		ByteBuffer bbuf = ByteBuffer.allocate(ipPacket.serialize());
		ByteBuffer payload = ByteBuffer.allocate(ipPacket.serialize().length - (int)ipPacket.getHeaderLength());
		bbuf.get(payload, (int)ipPacket.getHeaderLength(), payload.capacity());
		Data data = new Data(payload.array());

		//Set Payloads
		icmp.setPayload(data);	
		ip.setPayload(icmp);
		ether.setPayload(ip);
		return ether;
	}
}
