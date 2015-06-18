#include "xhci-mtk.h"
#include "xhci-mtk-power.h"
#include "xhci.h"
#include <linux/kernel.h>       /* printk() */
#include <linux/slab.h>
#include <linux/delay.h>

static int g_num_u3_port;
static int g_num_u2_port;

void enableXhciAllPortPower(struct xhci_hcd *xhci){
	int i;
	u32 port_id, temp;
	u32 __iomem *addr;

	addr = (void *) SSUSB_IP_CAP;
	g_num_u3_port = SSUSB_U3_PORT_NUM(readl(addr));
	g_num_u2_port = SSUSB_U2_PORT_NUM(readl(addr));
	
	for(i=1; i<=g_num_u3_port; i++){
		port_id=i;
		addr = &xhci->op_regs->port_status_base + NUM_PORT_REGS * ((port_id - 1) & 0xff);
		temp = xhci_readl(xhci, addr);
		temp = xhci_port_state_to_neutral(temp);
		temp |= PORT_POWER;
		xhci_writel(xhci, temp, addr);
	}
	for(i=1; i<=g_num_u2_port; i++){
		port_id=i+g_num_u3_port;
		addr = &xhci->op_regs->port_status_base + NUM_PORT_REGS * ((port_id - 1) & 0xff);
		temp = xhci_readl(xhci, addr);
		temp = xhci_port_state_to_neutral(temp);
		temp |= PORT_POWER;
		xhci_writel(xhci, temp, addr);
	}
}

void enableAllClockPower(void){

	int i;
	u32 temp;
	u32 __iomem *addr;

	addr = (void *) SSUSB_IP_CAP;
	g_num_u3_port = SSUSB_U3_PORT_NUM(readl(addr));
	g_num_u2_port = SSUSB_U2_PORT_NUM(readl(addr));

	//2.	Enable xHC
	addr = (void *) SSUSB_IP_PW_CTRL;
	writel(readl(addr) | (SSUSB_IP_SW_RST), addr);
	writel(readl(addr) & (~SSUSB_IP_SW_RST), addr);

	addr = (void *) SSUSB_IP_PW_CTRL_1;
	writel(readl(addr) & (~SSUSB_IP_PDN), addr);
	
	//1.	Enable target ports 
	for(i=0; i<g_num_u3_port; i++){
		addr = (void *) SSUSB_U3_CTRL(i);
		temp = readl(addr) & (~SSUSB_U3_PORT_PDN) & (~SSUSB_U3_PORT_DIS);
		writel(temp, addr);
	}
	for(i=0; i<g_num_u2_port; i++){
		addr = (void *) SSUSB_U2_CTRL(i);
		temp = readl(addr) & (~SSUSB_U2_PORT_PDN) & (~SSUSB_U2_PORT_DIS);
		writel(temp, addr);
	}
	msleep(100);
}


//(X)disable clock/power of a port 
//(X)if all ports are disabled, disable IP ctrl power
//disable all ports and IP clock/power, this is just mention HW that the power/clock of port 
//and IP could be disable if suspended.
//If doesn't not disable all ports at first, the IP clock/power will never be disabled
//(some U2 and U3 ports are binded to the same connection, that is, they will never enter suspend at the same time
//port_index: port number
//port_rev: 0x2 - USB2.0, 0x3 - USB3.0 (SuperSpeed)
void disablePortClockPower(void){
	int i;
	u32 temp;
	u32 __iomem *addr;

	addr = (void *) SSUSB_IP_CAP;
	g_num_u3_port = SSUSB_U3_PORT_NUM(readl(addr));
	g_num_u2_port = SSUSB_U2_PORT_NUM(readl(addr));
	
	for(i=0; i<g_num_u3_port; i++){
		addr = (void *) SSUSB_U3_CTRL(i);
		temp = readl(addr) | (SSUSB_U3_PORT_PDN);
		writel(temp, addr);
	}
	for(i=0; i<g_num_u2_port; i++){
		addr = (void *) SSUSB_U2_CTRL(i);
		temp = readl(addr) | (SSUSB_U2_PORT_PDN);
		writel(temp, addr);
	}

	addr = (void *) SSUSB_IP_PW_CTRL_1;
	writel(readl(addr) | (SSUSB_IP_PDN), addr);
}

//if IP ctrl power is disabled, enable it
//enable clock/power of a port
//port_index: port number
//port_rev: 0x2 - USB2.0, 0x3 - USB3.0 (SuperSpeed)
void enablePortClockPower(int port_index, int port_rev){
	u32 temp;
	u32 __iomem *addr;
	
	addr = (void *) SSUSB_IP_PW_CTRL_1;
	writel(readl(addr) & (~SSUSB_IP_PDN), addr);

	if(port_rev == 0x3){
		addr = (void *) SSUSB_U3_CTRL(port_index);
		temp = readl(addr) & (~SSUSB_U3_PORT_PDN);
		writel(temp, addr);
	}
	else if(port_rev == 0x2){
		addr = (void *) SSUSB_U2_CTRL(port_index);
		temp = readl(addr) & (~SSUSB_U2_PORT_PDN);
		writel(temp, addr);
	}
}

