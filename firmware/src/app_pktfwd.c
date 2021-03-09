#include <app_pktfwd.h>

#include <tcpip/tcpip.h>
#include <tcpip/udp.h>
#include <tcpip/tcpip_helpers.h>

#include "app.h"

static bool enabled = false;

static APP_DATA_PKTFWD        appData = {0};
extern APP_GW_ACTIVATION_DATA appGWActivationData;

struct pktfwd_state {
    UDP_SOCKET socket;
    IP_MULTI_ADDRESS address;
    uint16_t port;
};

static struct pktfwd_state state;

bool APP_PKTFWD_Init()
{
    appData.state = APP_PKTFWD_INIT;
    appData.rx_pkt_cnt = 0;
    appData.tx_pkt_cnt = 0;
    enabled = true;
    return true;
}

int sendUDPPacket(char* data, int len)
{
    SYS_PRINT("PKTFWD: Sent udp packet\r\n");
/*    
    // rebind the udp socket if the local address has changed.
    TCPIP_NET_HANDLE netif = TCPIP_STACK_NetDefaultGet();
    IP_MULTI_ADDRESS a;
    a.v4Add.Val = TCPIP_STACK_NetAddress(netif);

    TCPIP_UDP_Bind(state.socket, IP_ADDRESS_TYPE_IPV4, 4242, &a);


    if (!TCPIP_UDP_DestinationIPAddressSet(state.socket, IP_ADDRESS_TYPE_IPV4, &state.address)) {
    	SYS_PRINT("PKTFWD: Unable to send dest IP\r\n");
	return;
    }

    if (!TCPIP_UDP_DestinationPortSet(state.socket, state.port)) {
    	SYS_PRINT("PKTFWD: Unable to send dest port\r\n");
	return;
    }
*/    
    int bytes_avail = TCPIP_UDP_PutIsReady(state.socket);
    if (bytes_avail < len) {
    	SYS_PRINT("PKTFWD: Not enough buffer size %d, requested %d\r\n", bytes_avail, len);
	return;
    }

    int bytes_put = TCPIP_UDP_ArrayPut(state.socket, data, len);
    if (bytes_put != len) {
    	SYS_PRINT("PKTFWD: put less bytes %d, requested %d\r\n", bytes_put, len);
    }

    int bytes_sent = TCPIP_UDP_Flush(state.socket);
    if (bytes_sent != len) {
    	SYS_PRINT("PKTFWD: sent less bytes %d, requested %d\r\n", bytes_sent, len);
    }   
}

int sendUplink()
{
    SYS_PRINT("PKTFWD: sendUplink\r\n");

    loraRXPacket          recv_packet = {0};
    dequeueLoRaRX(&recv_packet);

    //TODO: send
    sendUDPPacket("ahoj", 4);
    int err = 0;

    if (err != 0 && recv_packet.uploadretry < 3)
    {
        // Place the failed LoRa packet back in the queue
        recv_packet.uploadretry += 1;
        enqueueLoRaRX(&recv_packet);
        return err;
    }
    appData.rx_pkt_cnt++;
    return err;
}

void getPacketCount(uint32_t* pup, uint32_t* pdown)
{
    *pup   = appData.rx_pkt_cnt;
    *pdown = appData.tx_pkt_cnt;
    return;
}

int lastreport = 0;

void APP_PKTFWD_Process(void) {
    int nowsec = SYS_TMR_TickCountGet() / SYS_TMR_TickCounterFrequencyGet();
    if (nowsec > lastreport) {
    	//SYS_PRINT("PKTFWD: Running...\r\n");
	lastreport = nowsec;
    }
    if (hasLoraRXPacketInQueue()) {
	sendUplink();
    }
}

void APP_PKTFWD_Tasks(void) {
    if (!enabled) {
        return;
    }

    switch(appData.state)
    {
        case APP_PKTFWD_INIT:
            SYS_PRINT("PKTFWD: Initializing...\r\n");

            state.port = appGWActivationData.configuration.pktfwd_port;

            if ((state.port < 1) || (state.port > 65535)) {
            	state.port = 1700;
            }
        
            TCPIP_DNS_RESULT result = TCPIP_DNS_Resolve(appGWActivationData.configuration.pktfwd_server, TCPIP_DNS_TYPE_A);
            if(result == TCPIP_DNS_RES_NAME_IS_IPADDRESS)
            {
                SYS_PRINT("PKTFWD: server specified as IP address %s\r\n", appGWActivationData.configuration.pktfwd_server);
        
        	if (!TCPIP_Helper_StringToIPAddress(appGWActivationData.configuration.pktfwd_server, &state.address.v4Add)) {
                    SYS_PRINT("PKTFWD: Failed to convert IP address to object\r\n");
		    appData.state = APP_PKTFWD_FAILED;
                    return;
		}
	    }
	    appData.state = APP_PKTFWD_RESOLVE;
	break;
        case APP_PKTFWD_RESOLVE:
	{
            IP_MULTI_ADDRESS mAddr;
            
            TCPIP_DNS_RESULT result = TCPIP_DNS_IsResolved(appGWActivationData.configuration.pktfwd_server, &mAddr, IP_ADDRESS_TYPE_IPV4);
            
            switch(result)
            {
                case TCPIP_DNS_RES_PENDING:
		    return;
                case TCPIP_DNS_RES_OK:
                    // We now have an IPv4 Address
                    // Open a socket
            	    state.address.v4Add = mAddr.v4Add;
		    char ipaddr[20];
		    TCPIP_Helper_IPAddressToString(&state.address.v4Add, (char*)(&ipaddr), 20);
                    SYS_PRINT("PKTFWD: DNS resolved: %s\r\n", ipaddr);
		    appData.state = APP_PKTFWD_CONNECT;
                    return;
                case TCPIP_DNS_RES_SERVER_TMO:
                    SYS_PRINT("PKTFWD: DNS resolve timeout\r\n");
		    appData.state = APP_PKTFWD_FAILED;
                    return;
                case TCPIP_DNS_RES_NO_IP_ENTRY:
                    SYS_PRINT("PKTFWD: NO IP record found\r\n");
		    appData.state = APP_PKTFWD_FAILED;
                    return;
                default:
                    SYS_DEBUG(SYS_ERROR_FATAL, "HTTP: TCPIP_DNS_IsResolved returned failure code %d\r\n", result);
		    appData.state = APP_PKTFWD_FAILED;
                    return;
            }
	}
	break;
	case APP_PKTFWD_CONNECT:
            state.socket = TCPIP_UDP_ClientOpen(IP_ADDRESS_TYPE_IPV4, state.port, &state.address);

            if (state.socket == INVALID_UDP_SOCKET) {
    	        SYS_PRINT("PKTFWD: Failed to create socket %d\r\n", state.socket);
		appData.state = APP_PKTFWD_FAILED;
                return;
	    }
            SYS_PRINT("PKTFWD: Initialized server %s:%d\r\n", appGWActivationData.configuration.pktfwd_server, state.port);
            appData.state = APP_PKTFWD_PROCESS;
	    return;
        case APP_PKTFWD_PROCESS:
	    APP_PKTFWD_Process();
        case APP_PKTFWD_FAILED:
	    return;
    }

}

