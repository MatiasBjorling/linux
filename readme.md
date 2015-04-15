# LightNVM - Linux kernel support for Open-channel SSDs

Open-channel SSDs are devices that share responsibilities with the host
in order to implement and maintain features that typical SSDs keep
strictly in firmware. These include (i) the Flash Translation Layer
(FTL), (ii) bad block management, and (iii) hardware units such as the
flash controller, the interface controller, and large amounts of flash
chips. In this way, Open-channels SSDs can expose direct
access to their physical flash storage, while keeping a subset of the
internal features of SSDs.

LightNVM is a specification that gives support to Open-channel SSDs.
LightNVM allows the host to manage data placement, garbage collection,
and parallelism. Device specific responsibilities such as bad block
management, FTL extensions to support atomic IOs, or metadata
persistence are still handled by the device.

The architecture of LightNVM consists of two parts: core and (multiple)
targets. The core implements functionality shared across targets. This
is initialization, teardown and statistics. The targets implement the
interface that exposes physical flash to user-space applications.
Examples of such targets include key-value store, object-store, as well
as traditional block devices, which can be application-specific.

Currently, LightNVM is hooked up through the null_blk and NVMe driver.
The NVMe extension allow development using the LightNVM-extended QEMU
implementation, using Keith Busch's qemu-nvme branch.

Development is taking place at:
https://github.com/OpenChannelSSD/

# How to use
-------------
To use LightNVM, a device is required to register as an open-channel
SSD.

There exist two implementations at the moment: null_blk and NVMe driver.
The null_blk driver is intended for performance testing. The NVMe driver
can be initialized using the patches of Keith Busch's QEMU NVMe
simulator, as well as using an Open-channel SSD device.

The QEMU branch is available at:
https://github.com/OpenChannelSSD/qemu-nvme

Follow the guide at: https://github.com/OpenChannelSSD/linux/wiki

# LightNVM Specification

We are actively creating a specification as more and more of the
host/device interface is stabilized. Please see this Google document.
It's open for comments.

http://goo.gl/BYTjLI

# Available Hardware

A number of open platforms are being ported to utilize LightNVM:

- IIT Madras (https://bitbucket.org/casl/ssd-controller) An open-source
implementation of a NVMe controller in BlueSpec. Can run on Xilix
FPGA's such as Artix 7, Kintex 7, and Vertex 7.

- MemBlaze eBlaze (https://github.com/OpenChannelSSD/memblaze-eblaze) A
high-performance SSD that exposes direct flash to the host. The device
driver is in progress.

A number of stealth hardware startups are supporting LightNVM directly
in their designs. Please contact us for more information.

- Other platform such as OpenSSD Jasmine and OpenSSD Cosmos are able to
support LightNVM. However, there is no compatible firmwares yet.

# Contact:
You can contact us at:
	matias@paletta.io
	javier@paletta.io

