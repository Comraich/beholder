# Beholder

### Simple web app that visualizes internet traffic on a network
### Written in Go and JavaScript

## Instructions for use:

### Requirements:

You will need a router or firewall that is capable of mirroring ports. Some routers have this capability built in, notaqbly routers running DDwrt, OpnSensen, and PFSense. Most enterprise or "prosumer"-devices have this capability.

Furthermore you will need a device that can run beholder. I have tested Raspberry 4 and 5, both work just fine. On a Pi you will need to use the Wifi to connect to your internal network, or a USB-based ethernet dongle. The internal ethernet port should be used as the capture port for your internet-traffic, as this can be a substantial ammount of traffic. 


       .--.
    .-(    ). ------[Firewall]--------[Internal network]
   (___.__)__)           |.                    |
                         |-----[Beholder]------|

This allows the beholder to "see" all traffic running to and from your router/firewall, thus allowing for the visualization.

If your firewall is unable to provide a mirrored port, you can get around this be using a managed switch that can provide the mirrored port. In this case your setup will look something like this:

       .--.
    .-(    ). -------[Switch]-------[Firewall]-----[Internal network]
   (___.__)__)          |                                |
                        |------------[Beholder]----------|

Ubequity Networks line of Flex switches are a good cheap alternative that allow for mirrored ports.

### Installation

1. 