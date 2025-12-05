# Beholder

## Simple web app that visualizes internet traffic on a network, written in Go and JavaScript

### Requirements

You will need a router or firewall that is capable of mirroring ports. Some routers have this capability built in, notaqbly routers running DDwrt, OpnSensen, and PFSense. Most enterprise or "prosumer"-devices have this capability.

Furthermore you will need a device that can run beholder. I have tested Raspberry 4 and 5, both work just fine. On a Pi you will need to use the Wifi to connect to your internal network, or a USB-based ethernet dongle. The internal ethernet port should be used as the capture port for your internet-traffic, as this can be a substantial ammount of traffic.

       .--.
    .-(    ). ------[Firewall]--------[Internal network]
   (___.__)__)          |                    |
                        |-----[Beholder]-----|

This allows the beholder to "see" all traffic running to and from your router/firewall, thus allowing for the visualization.

If your firewall is unable to provide a mirrored port, you can get around this be using a managed switch that can provide the mirrored port. In this case your setup will look something like this:

       .--.
    .-(    ). -------[Switch]-------[Firewall]-----[Internal network]
   (___.__)__)          |                                |
                        |------------[Beholder]----------|

Ubequity Networks line of Flex switches are a good cheap alternative that allow for mirrored ports.

### Installation

It is assumed that the server you are installing to is a Linux-server. I have successfully tested the software on Fedora, Ubuntu, Debian, and NixOS. It was written on a Macbook, so it is likely to work just fine on MacOS as well. Theoretically it should work on Windows too, but I have never tried it.

1. Clone the repo to the computer you intend to run Beholder on
2. Give the install.sh script execution permission: 'chmod +x beholder.sh'
3. Run the installation script *as root*: sudo ./install.sh

The installer will now create a folder under /opt and install the systemd service for the application. The service is now available on port 8080.

If you intend to run this software in a larger scale than your house, I would suggest putting the service behind a reverse proxy. I have used CloudFlare as a reverse proxy with great success.

### Comments / Suggestions / Issues / Bugs / etc

Pull requests are welcome and encouraged.

If you identify a bug or other kind of issue in this software, please either create an issue here on GitHub (<https://github.com/Comraich/beholder/issues>), or shoot me an e-mail at <simon@gale-huset.net>. It may take some time for issues to be fixed, as this is not my dayjob.

Comments and suggestions can be sent to me at <simon@gale-huset.net>.

If you like this software, tell your friends about it. There is no cost involved, and it helps me spread my creation. If you didn't like it, this would be a nice time for some quiet contemplation.

### Copyright / legal stuff / all that jazz

This software is (C) Simon Bruce-Cassidy and Comraich, 2025.

The software is made available to you under the terms of the Apache 2.0 license. The full text of the license is available for your perusal in the LICENSE.txt.

This software uses the free versions of MaxMinds Geolite databases. These databases are (C) MaxMind and are provided by them. See <https://www.maxmind.com> for more information.

Maps are provided by OpenStreetMap. See <https://www.openstreetmap.org/copyright> for copyright information.
