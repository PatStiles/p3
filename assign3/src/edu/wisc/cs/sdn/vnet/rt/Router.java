package edu.wisc.cs.sdn.vnet.rt;

import java.nio.ByteBuffer;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;
import edu.wisc.cs.sdn.vnet.rt.RouteTable.tableEntry;
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

	/**
	 * Creates a router for a specific host.
	 * @param host hostname for the router
	 */
	public Router(String host, DumpFile logfile)
	{
		super(host,logfile);
		this.routeTable = new RouteTable(this);
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
		// Handle RIP packets
		if (ipPacket.getProtocol() == IPv4.PROTOCOL_UDP && ((UDP)ipPacket.getPayload()).getDestinationPort() == UDP.RIP_PORT)
		{
			System.out.println("Handle RIP packet");
			handleRipPacket(etherPacket, inIface);
			return;
		}

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
					if (icmpMsg != null)
					{ this.sendPacket(icmpMsg, iface); }
					return; 
				}

				if(ipPacket.getProtocol() == IPv4.PROTOCOL_ICMP)
				{
					Ethernet icmpMsg = genEchoMsg((byte) 0, (byte) 0,etherPacket, inIface);
					if (icmpMsg != null)
					{ this.sendPacket(icmpMsg, iface); }
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
			this.sendPacket(icmpMsg, inIface);
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
		icmp.resetChecksum();

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
		icmp.resetChecksum();

		//Set Data for ICMP Header
		//If cast of getHeaderLength() is invalid try Byte.toUnsignedInt
		//This creates a ByteBuffer of the entire IPv4 message then slice it and removes the IPv4 header. Instructions weren't that clear on what ethe spec is???
		//ByteBuffer bbuf = ByteBuffer.allocate(ipPacket.serialize().length);
		//ByteBuffer payload = ByteBuffer.allocate(ipPacket.serialize().length - (int)ipPacket.getHeaderLength());
		//bbuf.get(payload.array(), (int)ipPacket.getHeaderLength(), payload.capacity());
		//Data data = new Data(payload.array());

		//Set Payloads -> Should be original payload of ICMP
		icmp.setPayload(((ICMP)ipPacket.getPayload()).getPayload());	
		ip.setPayload(icmp);
		ether.setPayload(ip);
		return ether;
	}

	public void handleRipPacket(Ethernet etherPacket, Iface inIface) 
	{
		// TODO: Update route table
		IPv4 ip = (IPv4)etherPacket.getPayload();
		UDP udp = (UDP)ip.getPayload();
		RIPv2 rip = (RIPv2)udp.getPayload();

		if (rip.getCommand() == RIPv2.COMMAND_RESPONSE)
		{
			if (this.routeTable.getRipEntry(inIface.getIpAddress() & inIface.getSubnetMask(), inIface.getSubnetMask()) == null)
			{
				RIPv2Entry entry = new RIPv2Entry();
				entry.setAddress(inIface.getIpAddress() & inIface.getSubnetMask());
				entry.setSubnetMask(inIface.getSubnetMask());
				entry.setMetric(16);
				this.routeTable.addRipEntry(entry);
			}

			tableEntry network = this.routeTable.getRipEntry(inIface.getIpAddress() & inIface.getSubnetMask(), inIface.getSubnetMask());
			boolean changesMade = false;

			for (RIPv2Entry entry : rip.getEntries())
			{
				RouteEntry match = this.routeTable.find(entry.getAddress(), entry.getSubnetMask());
				int newCost = Math.min(entry.getMetric() + network.ripEntry.getMetric(), 16);
				entry.setMetric(newCost);
				System.out.println("entry " + entry.getMetric());
				System.out.println("network " + network.ripEntry.getMetric());
				System.out.println("cost " + newCost);

				if (match != null && match.isRipEntry())
				{
					RIPv2Entry oldEntry = this.routeTable.getRipEntry(entry).ripEntry;

					if (match.getGatewayAddress() == ip.getSourceAddress())
					{
						if (entry.getMetric() > 15)
						{
							this.routeTable.removeRipEntry(oldEntry);
							this.routeTable.remove(oldEntry.getAddress(), oldEntry.getSubnetMask());
						}
						else
						{
							if (oldEntry.getMetric() != newCost)
							{
								changesMade = true;
							}

							oldEntry.setMetric(newCost);
							match.setMetric(newCost);
							this.routeTable.addRipEntry(entry);
						}
					}
					else if (oldEntry.getMetric() < newCost)
					{
						if (entry.getMetric() > 15)
						{
							this.routeTable.removeRipEntry(oldEntry);
							this.routeTable.remove(oldEntry.getAddress(), oldEntry.getSubnetMask());
						}
						else
						{
							// Found a shorter path
							this.routeTable.removeRipEntry(entry);

							// Update route table with new entry
							match.setMetric(newCost);

							// Update old RIP entry
							oldEntry.setMetric(newCost);

							this.routeTable.addRipEntry(entry);
							changesMade = true;
						}
					}
				}
				else if (match == null)
				{
					this.routeTable.addRipEntry(entry);
					this.routeTable.insert(entry.getAddress(), ip.getSourceAddress(), entry.getSubnetMask(), inIface, newCost);
				}

				if (changesMade)
				{
					System.out.println("-----Updated route table-----");
					System.out.println(this.routeTable.toString());
					System.out.println("-----------------------------");

					this.floodRIPResp();
				}
			}		
		}
		else
		{
			// Send response for the given request
			this.sendRipResponse(inIface);
		}
	}

	public void buildRipRouteTable()
	{
		// Add RouteTable entries for directly reachable subnets
		// QUESTION: Should we check if these interfaces are directly reachable by checking if gateway address is 0, the definition of durectly reachable is not understood. Can we assume the initial interfaces are the ones that are directly reachable???
		for (Iface iface : this.interfaces.values())
		{
			int destinationAddress = iface.getIpAddress() & iface.getSubnetMask();
			System.out.println(iface.getIpAddress());
			System.out.println(destinationAddress);
			int maskAddress = iface.getSubnetMask();

			this.routeTable.insert(destinationAddress, EMPTY_GATEWAY_ADDRESS, maskAddress, iface, 1);
		}

		System.out.println("Loaded route table from directly reachable subnets");
		System.out.println("-------------------------------------------------");
		System.out.print(this.routeTable.toString());
		System.out.println("-------------------------------------------------");

		this.broadcastRIP();
		this.routeTable.startRipThread();
	}

	private void broadcastRIP()
	{
		for (Iface iface : this.interfaces.values())
		{
			Ethernet etherPacket = new Ethernet();
			etherPacket.setSourceMACAddress(iface.getMacAddress().toString());
			etherPacket.setDestinationMACAddress(RIP_MAC_ADDRESS.toString());
			etherPacket.setEtherType(Ethernet.TYPE_IPv4);

			//Create new IPv4 packet
			IPv4 ip = new IPv4();
			ip.setTtl((byte)64);
			ip.setProtocol(IPv4.PROTOCOL_UDP);
			ip.setSourceAddress(iface.getIpAddress());
			ip.setDestinationAddress(RIP_IP_ADDRESS);

			UDP udpPacket = new UDP();
			udpPacket.setDestinationPort(UDP.RIP_PORT);

			RIPv2 rip = new RIPv2();
			rip.setCommand(RIPv2.COMMAND_REQUEST);

			udpPacket.setPayload(rip);
			ip.setPayload(udpPacket);
			etherPacket.setPayload(ip);
			this.sendPacket(etherPacket, iface);
		}
	}

	public void floodRIPResp()
	{
		System.out.println("Flood RIP Responses");

		for (Iface iface : this.interfaces.values())
		{
			Ethernet etherPacket = new Ethernet();
			etherPacket.setSourceMACAddress(iface.getMacAddress().toString());
			etherPacket.setDestinationMACAddress(RIP_MAC_ADDRESS.toString());
			etherPacket.setEtherType(Ethernet.TYPE_IPv4);

			IPv4 ip = new IPv4();
			ip.setTtl((byte)64);
			ip.setProtocol(IPv4.PROTOCOL_UDP);
			ip.setSourceAddress(iface.getIpAddress());
			ip.setDestinationAddress(RIP_IP_ADDRESS);

			UDP udpPacket = new UDP();
			udpPacket.setDestinationPort(UDP.RIP_PORT);

			RIPv2 rip = new RIPv2();
			rip.setCommand(RIPv2.COMMAND_RESPONSE);

			for (RouteEntry tableEntry : this.routeTable.getEntries())
			{
				RIPv2Entry ripEntry = new RIPv2Entry();

				ripEntry.setAddress(tableEntry.getDestinationAddress());
				ripEntry.setSubnetMask(tableEntry.getMaskAddress());
				ripEntry.setMetric(tableEntry.getMetric());

				rip.addEntry(ripEntry);
			}
			
			udpPacket.setPayload(rip);
			ip.setPayload(udpPacket);
			etherPacket.setPayload(ip);
			this.sendPacket(etherPacket, iface);
		}
	}

	private void sendRipResponse(Iface inIface)
	{
		System.out.println("Send RIP response");

		Ethernet etherPacket = new Ethernet();
		etherPacket.setSourceMACAddress(inIface.getMacAddress().toString());
		etherPacket.setDestinationMACAddress(inIface.getMacAddress().toString());
		etherPacket.setEtherType(Ethernet.TYPE_IPv4);

		IPv4 ip = new IPv4();
		ip.setTtl((byte)64);
		ip.setProtocol(IPv4.PROTOCOL_UDP);
		ip.setSourceAddress(inIface.getIpAddress());
		ip.setDestinationAddress(inIface.getIpAddress());

		UDP udpPacket = new UDP();
		udpPacket.setDestinationPort(UDP.RIP_PORT);

		RIPv2 rip = new RIPv2();
		rip.setCommand(RIPv2.COMMAND_RESPONSE);

		for (RouteEntry tableEntry : this.routeTable.getEntries())
		{
			RIPv2Entry ripEntry = new RIPv2Entry();

			ripEntry.setAddress(tableEntry.getDestinationAddress());
			ripEntry.setSubnetMask(tableEntry.getMaskAddress());
			ripEntry.setMetric(tableEntry.getMetric());
			ripEntry.setNextHopAddress(tableEntry.getDestinationAddress());

			rip.addEntry(ripEntry);
		}
		
		udpPacket.setPayload(rip);
		ip.setPayload(udpPacket);
		etherPacket.setPayload(ip);
		this.sendPacket(etherPacket, inIface);
	}
}
