# Beholder

### Simple web app that visualizes internet traffic on a network
### Written in Go and JavaScript

## Instructions for use:

### Requirements:

You will need a router or firewall that is capable of mirroring ports. Some routers have this capability built in, notaqbly routers running DDwrt, OpnSensen, and PFSense. If your router is not capable of this, you can use a managed switch between your router and internet connection.

Furthermore you will need a device that can run beholder. I have tested Raspberry 4 and 5, both work just fine. On a Pi you will need to use the Wifi to connect to your internal network, or a USB-based ethernet dongle. The internal ethernet port should be used as the capture port for your internet-traffic, as this can be a not unsubstantial ammount of traffic. 

       .--.
    .-(    ). -------------[Beholder device]---------------[Firewall]-----------------[Internal network]
   (___.__)__)                     |                                                             |
                                   | ----------------------------------------------------------- |

This allows the beholder to "see" all traffic running to and from your router/firewall, thus allowing for the visualization