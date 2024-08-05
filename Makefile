DRV_VER_NUM=5.2.1.2

# For RZ CIP kernel build, currently kernel 5.10.131
KDIR ?= /home/rzg2l-5.10.158
# For RZ VLP 3.0.3, kernel 5.10.158
# KDIR ?= /home/liam/work/RZG_VLP_v3/v303/build/tmp/work/smarc_rzg2l-poky-linux/linux-renesas/5.10.158-cip22+gitAUTOINC+4f3d2d21ad-r1/linux-smarc_rzg2l-standard-build
# For General kernel build, for example, kernel 6.1
# KDIR ?= /home/liam/work/linux-stable/.out

# Support of P2P DebugFS for enabling/disabling NoA and OppPS
CONFIG_RS_P2P_DEBUGFS ?= y

# Enable BEACON transmission (need FW support)
CONFIG_RS_BCN ?= y

# Enable the host tx no kickback feature
CONFIG_HOST_TX_NO_KICKBACK ?= y

# Enable merge tx data (default is disable)
CONFIG_HOST_TX_MERGE ?= n

# Set module type (sdio or spi, default is sdio)
CONFIG_MODULE_TYPE ?= sdio

CONFIG_CHIP_TYPE ?= da16200

ifeq ($(CONFIG_MODULE_TYPE), sdio)
# Using SDIO interface
EXTRA_CFLAGS += -DCONFIG_RS_SDIO
CONFIG_RS_SDIO ?= y
interface="SDIO"
endif

ifeq ($(CONFIG_MODULE_TYPE), spi)
# Using SPI interface
EXTRA_CFLAGS += -DCONFIG_RS_SPI
CONFIG_RS_SPI ?= y
interface="SPI"
endif

ifeq ($(CONFIG_CHIP_TYPE), da16200)
chip="DA16200"
else
chip="RRQ61000"
endif

# extra DEBUG config
CONFIG_RS_DBG ?= n

CONFIG_SUPPORT_5G ?= n

CONFIG_DEBUG_BUILD ?= n

obj-m += rswlan.o
rswlan-y := rs_mgmt_tx.o           \
              rs_mgmt_rx.o         \
              rs_utils.o           \
              rs_irq.o             \
              rs_irq_dbg.o         \
              rs_irq_misc.o        \
              rs_irq_rx.o          \
              rs_irq_tx_kb.o       \
              rs_rx.o              \
              rs_tx.o              \
              rs_main.o            \
              rs_params.o          \
              rs_core.o            \
              rs_mac80211.o        \
              rs_priv.o            \
              rs_file.o

rswlan-$(CONFIG_RS_SDIO) += rs_sdio.o rs_sdio_ops.o
rswlan-$(CONFIG_RS_SPI)  += rs_spi.o rs_spi_ops.o
rswlan-$(CONFIG_DEBUG_FS)         += rs_debugfs.o
rswlan-$(CONFIG_NL80211_TESTMODE) += rs_testmode.o

ccflags-y += -I$(src)
ccflags-y += -Wframe-larger-than=2048

ccflags-$(CONFIG_DEBUG_FS) += -DCONFIG_RS_DEBUGFS
ccflags-$(CONFIG_DEBUG_FS) += -DCONFIG_RS_UM_HELPER_DFLT=\"$(CONFIG_RS_UM_HELPER_DFLT)\"
ccflags-$(CONFIG_RS_P2P_DEBUGFS) += -DCONFIG_RS_P2P_DEBUGFS
ccflags-$(CONFIG_HOST_TX_NO_KICKBACK) += -DCONFIG_HOST_TX_NO_KICKBACK

# FW VARS
ccflags-y += -DRS_VIF_DEV_MAX=4
ccflags-y += -DRS_REMOTE_STA_MAX=5
ccflags-y += -DRS_MU_GROUP_MAX=1
ccflags-y += -DRS_TXDESC_CNT=64
ccflags-y += -DRS_TX_MAX_RATES=4
ccflags-y += -DRS_CHAN_CTXT_CNT=3
ccflags-y += -DMODULE_VER_NUM=\"$(DRV_VER_NUM)\"
ccflags-$(CONFIG_DEBUG_BUILD) += -g -DDEBUG

# FW ARCH:
ccflags-$(CONFIG_RS_BCN) += -DCONFIG_RS_BCN
ccflags-$(CONFIG_RS_DBG) += -DCONFIG_RS_DBG
ccflags-$(CONFIG_SUPPORT_5G) += -DCONFIG_SUPPORT_5G

ccflags-y += -DCONFIG_USER_MAX=1

ifeq ($(CONFIG_RS_BCN), y)
ccflags-y += -DRS_TXQ_CNT=5
else
ccflags-y += -DRS_TXQ_CNT=4
endif

EXTRA_CFLAGS += -DDEBUG

all: version_gen.h
	$(MAKE) -C $(KDIR) M=$(PWD) modules

modules clean:
	$(MAKE) -C  $(KDIR) M=$(PWD) clean
    $(shell rm -f version_gen.h)
    $(shell rm -f *.o.cmd)

# make version_gen.h includes version info and compile time
version_gen.h:
	@echo "#define VERSION \"$(chip) $(interface) version: v$(DRV_VER_NUM)\"" > version_gen.h
	@echo "#define COMPILE_TIME \" - build: $(shell date '+%Y-%m-%d %H:%M:%S')\"" >> version_gen.h