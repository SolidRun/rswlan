#ifndef RS_IO_MAP_H
#define RS_IO_MAP_H

////////////////////////////////////////////////////////////////////////////////
/// INCLUDE

////////////////////////////////////////////////////////////////////////////////
/// MACRO DEFITION

#define FW_IO_MGMT_RX_IDX()	(((u8 *)(core->bus.irq_value)) + 0)
#define FW_IO_KB_IDX()		(((u8 *)(core->bus.irq_value)) + 1)
#define FW_IO_RX_IDX()		(((u8 *)(core->bus.irq_value)) + 2)
#define FW_IO_DBG_IDX()		(((u8 *)(core->bus.irq_value)) + 3)

/* RAM0 size 45k */
#define FW_IO_IRQ_STATUS_SIZE	(4)
#define FW_IO_MGMT_RX_ADDR_SIZE (4)
#define FW_IO_MGMT_TX_ADDR_SIZE (4)
#define FW_IO_DBG_MSG_ADDR_SIZE (4)
#define FW_IO_MAC_ADDR_SIZE	(8)
#define FW_IO_HWQ_LEN_ADDR_SIZE (4)
#define FW_IO_KB_ADDR_SIZE	(4)
#define FW_IO_NO_KB_SIZE	(4)
#define FW_IO_RX_ADDR_SIZE	(4)
#define FW_IO_TX_ADDR_SIZE	(4)

#define FW_IO_TOTAL_SIZE                                                                                \
	(FW_IO_IRQ_STATUS_SIZE + FW_IO_MGMT_RX_ADDR_SIZE + FW_IO_MGMT_TX_ADDR_SIZE +                    \
	 FW_IO_DBG_MSG_ADDR_SIZE + FW_IO_MAC_ADDR_SIZE + FW_IO_HWQ_LEN_ADDR_SIZE + FW_IO_KB_ADDR_SIZE + \
	 FW_IO_NO_KB_SIZE + FW_IO_RX_ADDR_SIZE + FW_IO_TX_ADDR_SIZE)

#define FW_IO_BASE_ADDR	     (0x00080000)
#define FW_IO_IRQ_STATUS     (FW_IO_BASE_ADDR) // 0x000000 , Size 4
#define FW_IO_MGMT_RX_ADDR   (FW_IO_IRQ_STATUS + FW_IO_IRQ_STATUS_SIZE) // 0x000004 , Size 4
#define FW_IO_MGMT_TX_ADDR   (FW_IO_MGMT_RX_ADDR + FW_IO_MGMT_RX_ADDR_SIZE) // 0x000008 , Size 4
#define FW_IO_DBG_MSG_ADDR   (FW_IO_MGMT_TX_ADDR + FW_IO_MGMT_TX_ADDR_SIZE) // 0x00000C , Size 4
#define FW_IO_MAC_ADDR	     (FW_IO_DBG_MSG_ADDR + FW_IO_DBG_MSG_ADDR_SIZE) // 0x000010 , Size 8
#define FW_IO_HWQ_LEN_ADDR   (FW_IO_MAC_ADDR + FW_IO_MAC_ADDR_SIZE) // 0x000018 , Size 4
#define FW_IO_KB_ADDR	     (FW_IO_HWQ_LEN_ADDR + FW_IO_HWQ_LEN_ADDR_SIZE) // 0x00001C , Size 4
#define FW_IO_NO_KB	     (FW_IO_KB_ADDR + FW_IO_KB_ADDR_SIZE) // 0x000020 , Size 4
#define FW_IO_RX_ADDR	     (FW_IO_NO_KB + FW_IO_NO_KB_SIZE) // 0x000024 , Size 4
#define FW_IO_TX_ADDR	     (FW_IO_RX_ADDR + FW_IO_RX_ADDR_SIZE) // 0x000028 , Size 4

#define FW_IO_MGMT_RX_CNT    (30)

#define FW_IO_TXBUF_CNT	     (48)
#define FW_IO_TX_PACKET_SIZE (2048)

#define FW_IO_RXBUF_CNT	     (80)
#define FW_IO_RX_PACKET_SIZE (2048)

#define FW_IO_KB_CNT	     (40)

////////////////////////////////////////////////////////////////////////////////
/// TYPE DEFINITION

////////////////////////////////////////////////////////////////////////////////
/// GLOBAL VARIABLE

////////////////////////////////////////////////////////////////////////////////
/// GLOBAL FUNCTION

#endif /* RS_IO_MAP_H */
