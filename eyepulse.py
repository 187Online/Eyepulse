
############################################################################
#
#                       Developed by 187Online 
#
#                          Version = 1.1
#       ___  __        __   __   __  ___ 
#    ███████╗██╗   ██╗███████╗    ██████╗ ██╗   ██╗██╗     ███████╗███████╗
#    ██╔════╝╚██╗ ██╔╝██╔════╝    ██╔══██╗██║   ██║██║     ██╔════╝██╔════╝
#    █████╗   ╚████╔╝ █████╗      ██████╔╝██║   ██║██║     ███████╗█████╗  
#    ██╔══╝    ╚██╔╝  ██╔══╝      ██╔═══╝ ██║   ██║██║     ╚════██║██╔══╝  
#    ███████╗   ██║   ███████╗    ██║     ╚██████╔╝███████╗███████║███████╗
#    ╚══════╝   ╚═╝   ╚══════╝    ╚═╝      ╚═════╝ ╚══════╝╚══════╝╚══════
#
############################################################################


import socket 
import time
import argparse
from scapy.all import *
from pythonping import ping
from banner import getbanner
from urllib.parse import urlparse
from prettytable import PrettyTable


RED,WHITE,GREEN,END =  '\033[1;91m', '\33[1;97m','\033[1;32m', '\033[0m'

class PortScanner : 
    
    def __init__(self) :
        
        getbanner()
 
        self.open_port_list = []
        
        self.filtered_port_list = []
        
        self.unfiltered_port_list = []
        
        self.udp_closed_filtered_list = []
        
        self.udp_open_lists = []
        
        self.ping_true_list = []
        
        self.port_list =[1, 2, 3, 4, 5, 7, 8, 9, 11, 13, 15, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
                     31, 33, 34, 35, 37, 38, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 
                     56, 57, 58, 59, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79,
                     80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 
                     103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121,
                     122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140,
                     141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159,
                     160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 171, 170, 172, 173, 174, 175, 176, 177, 178, 
                     179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197,
                     198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216,
                     217, 218, 219, 220, 221, 222, 223, 243, 245, 246, 344, 345, 346, 347, 348, 371, 372, 373, 374,
                     375, 376, 377, 378, 379, 380, 381, 382, 383, 384, 385, 386, 387, 388, 389, 390, 391, 392, 393,
                     394, 395, 396, 397, 398, 399, 400, 401, 402, 403, 404, 405, 406, 407, 408, 409, 410, 411, 412,
                     413, 414, 415, 416, 417, 418, 419, 420, 421, 422, 423, 424, 425, 426, 427, 428, 429, 430, 431,
                     432, 433, 434, 435, 436, 437, 438, 439, 440, 441, 442, 443, 444, 445, 446, 447, 448, 449, 450,
                     451, 452, 453, 454, 455, 456, 457, 458, 460, 459, 461, 462, 463, 464, 465, 466, 467, 468, 469,
                     470, 471, 472, 473, 474, 475, 512, 513, 514, 515, 517, 518, 519, 520, 525, 530, 531, 532, 533,
                     539, 540, 541, 543, 544, 545, 546, 547, 550, 551, 552, 553, 555, 556, 557, 558, 559, 560, 561,
                     562, 563, 564, 565, 566, 567, 568, 569, 570, 571, 572, 573, 600, 607, 606, 608, 609, 610, 611,
                     634, 666, 704, 709, 729, 730, 731, 741, 742, 744, 747, 748, 749, 750, 751, 752, 753, 754, 758, 
                     759, 760, 761, 762, 763, 764, 765, 767, 769, 770, 771, 772, 773, 774, 775, 776, 780, 786, 800, 
                     801, 888, 996, 997, 998, 999, 1000, 39, 242, 244, 247, 248, 256, 257, 258, 259, 260, 261, 262, 
                     263, 264, 265, 280, 281, 282, 308, 309, 310, 311, 312, 313, 314, 315, 316, 317, 321, 349, 350,
                     351, 352, 353, 354, 355, 356, 357, 358, 359, 360, 361, 362, 363, 364, 365, 366, 367, 368, 369,
                     370, 476, 477, 478, 479, 480, 481, 482, 483, 484, 485, 486, 487, 488, 489, 490, 491, 492, 493,
                     494, 495, 496, 497, 498, 499, 500, 501, 502, 503, 504, 505, 506, 507, 508, 509, 510, 511, 516, 
                     521, 522, 523, 524, 526, 527, 528, 529, 534, 535, 536, 537, 538, 542, 548, 549, 554, 574, 575,
                     576, 577, 578, 579, 580, 581, 582, 583, 584, 585, 586, 587, 588, 589, 590, 591, 592, 593, 594, 
                     595, 596, 597, 598, 599, 603, 617, 628, 631, 636, 637, 660, 674, 691, 706, 723, 740, 781, 782,
                     783, 799, 808, 871, 873, 898, 989, 901, 902, 903, 950, 953, 975, 990, 992, 993, 994, 995, 1002,
                     1008, 1023, 1024, 1025, 1026, 1027, 1029, 1030, 1031, 1032, 1033, 1040, 1043, 1050, 1058, 1059, 
                     1067, 1068, 1076, 1080, 1083, 1084, 1103, 1109, 1110, 1112, 1127, 1139, 1155, 1158, 1178, 1212, 
                     1214, 1220, 1222, 1234, 1241, 1248, 1337, 1346, 1347, 1348, 1349, 1350, 1351, 1352, 1353, 1354, 
                     1355, 1356, 1357, 1358, 1359, 1360, 1361, 1362, 1363, 1364, 1365, 1366, 1367, 1368, 1369, 1370,
                     1371, 1372, 1373, 1374, 1375, 1376, 1377, 1378, 1379, 1380, 1381, 1383, 1384, 1385, 1386, 1387, 
                     1388, 1389, 1390, 1391, 1392, 1393, 1394, 1395, 1396, 1397, 1398, 1399, 1400, 1401, 1402, 1403, 
                     1404, 1405, 1406, 1407, 1408, 1409, 1410, 1411, 1412, 1413, 1414, 1415, 1416, 1417, 1418, 1419, 
                     1420, 1421, 1422, 1423, 1424, 1425, 1426, 1427, 1428, 1429, 1430, 1431, 1432, 1433, 1434, 1435,
                     1436, 1437, 1438, 1439, 1440, 1441, 1442, 1443, 1444, 1445, 1446, 1447, 1448, 1449, 1450, 1451,
                     1452, 1453, 1454, 1455, 1456, 1457, 1458, 1459, 1460, 1461, 1462, 1463, 1464, 1465, 1466, 1467,
                     1468, 1469, 1470, 1471, 1472, 1473, 1474, 1475, 1476, 1477, 1478, 1479, 1480, 1481, 1482, 1483, 
                     1484, 1485, 1486, 1487, 1488, 1489, 1490, 1491, 1492, 1493, 1494, 1495, 1496, 1497, 1498, 1499, 
                     1500, 1501, 1502, 1503, 1504, 1505, 1506, 1507, 1508, 1509, 1510, 1511, 1512, 1513, 1514, 1515,
                     1516, 1517, 1518, 1519, 1520, 1521, 1522, 1523, 1524, 1525, 1526, 1527, 1528, 1529, 1530, 1531,
                     1532, 1533, 1534, 1535, 1536, 1537, 1538, 1539, 1540, 1541, 1542, 1543, 1544, 1545, 1546, 1547,
                     1548, 1549, 1550, 1551, 1552, 1600, 1650, 1651, 1652, 1661, 1662, 1663, 1664, 1665, 1666, 1667,
                     1668, 1669, 1670, 1671, 1672, 1680, 1720, 1723, 1755, 1761, 1762, 1763, 1764, 1827, 1900, 1935, 
                     1984, 1986, 1987, 1988, 1989, 1990, 1991, 1992, 1993, 1994, 1995, 1996, 1997, 1998, 1999, 2000, 
                     2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2011, 2012, 2013, 2014, 2015, 2016, 
                     2017, 2018, 2019, 2020, 2021, 2022, 2023, 2024, 2025, 2026, 2027, 2028, 2030, 2032, 2033, 2034, 
                     2035, 2038, 2040, 2041, 2042, 2043, 2044, 2045, 2046, 2047, 2048, 2049, 2064, 2053, 2065, 2067, 
                     2068, 2105, 2106, 2108, 2111, 2112, 2120, 2121, 2201, 2232, 2241, 2301, 2307, 2401, 2430, 2431,
                     2432, 2433, 2500, 2501, 2564, 2600, 2601, 2602, 2603, 2604, 2605, 2627, 2628, 2638, 2766, 2784,
                     2809, 2903, 2998, 3000, 3001, 3005, 3006, 3049, 3052, 3064, 3086, 3128, 3141, 3264, 3268, 3269,
                     3292, 3306, 3333, 3372, 3389, 3421, 3455, 3456, 3457, 3462, 3531, 3632, 3689, 3900, 3984, 3985, 
                     3986, 3999, 4000, 4008, 4045, 4125, 4132, 4133, 4144, 4224,40421, 4321, 4333, 4343, 4444, 4480,4500, 
                     4557, 4559, 4660, 4672, 4827, 4899, 4987, 4998, 5000, 5001, 5002, 5003, 5010, 5011, 5050, 5100, 
                     5101, 5102, 5145, 5060, 5190, 5191, 5192, 5193, 5232, 5236, 5300, 5301, 5302, 5303, 5304, 5305, 
                     5308, 5400, 5405, 5490, 5432, 5510, 5520, 5530, 5540, 5550, 5555, 5560, 5631, 5632, 5680, 5679, 
                     5713, 5714, 5715, 5716, 5717, 5800, 5801, 5802, 5803, 5900, 5901, 5902, 5903, 5977, 5978, 5979, 
                     5997, 5998, 5999, 6000, 6001, 6002, 6003, 6004, 6005, 6006, 6007, 6008, 6009, 6017, 6050, 6101, 
                     6103, 6105, 6106, 6110, 6111, 6112, 6141, 6142, 6143, 6144, 6145, 6146, 6147, 6148, 6346, 6400, 
                     6401, 6543, 6544, 6547, 6548, 6502, 6558, 6588, 6666, 6667, 6668, 6969, 6699, 7000, 7001, 7002, 
                     7003, 7004, 7005, 7006, 7007, 7008, 7009, 7010, 7070, 7100, 7200, 7201, 7273, 7326, 7464, 7597, 
                     7937, 7938, 8000, 8007, 8009, 8021, 8080, 8081, 8082, 8443, 8888, 8892, 9090, 9100, 9111, 9152, 
                     9535, 9876, 9991, 9992, 9999, 10000, 10005, 10082, 10083, 11371, 12000, 12345, 12346, 13701, 
                     13702, 13705, 13706, 13708, 13709, 13710, 13711, 13712, 13713, 13714, 13715, 13716, 13717]
    
    def usage(self) :
        print(WHITE + """
              
                                 EYEPULSE Port Scanner Tool 
              
--------------------------------------------------------------------------------------------------
                                                                                                  #
FLAGS :                      Description                               ARGS                       #
-gIP                         Get ip address of server                  -url                       #
-serverC                     Control server alive or down              -sA                        #
-spl                         Show port list                            None                       #
-fs                          Fast scan                                -sA -sT                     #
-fullS                       Full scan                                -sA -sT                     #
-rS                          Range scan                               -sA -pR -sT                 #
-pS                          Ping scan (Local)                         None                       #
-icmpS                       Icmp scan (Local)                         None                       #
-nR                          Net recon (Local)                         None                       #
-sS                          Stealth scan                             -sA -tO                     #
-tcpS                        TCP/ACK scan                             -sA -tO -sN                 # 
-xmas                        Xmas scan                                -sA -tO                     #
-zS                          Zombie scan                              -zB -vC -zP -tO             #
-uS                          UDP scan                                -sA -tO                      #
                                                                                                  #
---------------------------------------------------------------------------------------------------
                                            """ +END)
    
    
    
    def get_ip(self,url) :       
        
        try : 
            
            parsed_url = urlparse(url)     
        
            probe_packet = sr1(IP(dst=parsed_url.hostname)/ICMP(),verbose=False)
            
            url_data = GREEN +f"""
            Scheme : {parsed_url.scheme}
            Domain :  {parsed_url.netloc}
            Path   :  {parsed_url.path}
            Params : {parsed_url.params}
            Query  :   {parsed_url.query}
            ragment : {parsed_url.fragment}
            Ip Address : {probe_packet.src}
            """ + END
            
            print(url_data)
    
        except : 
            
            print(RED + 'CHECK URL'+END )

   
    def server_control(self,server_addr) :
       
        control_packet = IP(dst=server_addr)/ICMP()
        
        response = sr1(control_packet,timeout=5)
        
        if response == None : 
            
            print('SERVER DOWN')
       
        else : 
            
            print('SERVER UP')
    
    
    def show_ports(self) :
        
        print(self.port_list)    
   
         
    def net_show(self):
       
        network_table = PrettyTable(['IP ADDRESSS','DEVICE NAME','MAC ADDRESS'])
        
        for addr in self.ping_true_list :
           
            try : 
                
                network_table.add_row([addr,socket.gethostbyaddr(addr)[0],getmacbyip(addr)])
          
            except socket.error as error :
               
                network_table.add_row([addr,RED+'NONE'+ END])
      
        print(network_table)
    
    
    def scan(self,server_addr,port,on_off = 1) :
        
        try : 
            port = int(port)
            
            scanner = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
           
            scanner.settimeout(3) 
           
            response = scanner.connect_ex((server_addr,port))
           
            if response == 0 :
           
                on_off = response 
           
                scanner.close()
        
        except socket.error as error : 
        
            pass
        
        return on_off
    
    def fast_scan(self,server_addr,sleep_time=0):  
              
        print(RED + 'THIS METHOD USE ONLY COMMON PORTS IF NO RESULTS USE FULL SCAN OR RANGE SCAN' + END)
       
        print(GREEN +' [I] FAST SCAN STARTED... '+ END)
        
        common_ports  =['7', '20', '21', '22', '23', '25', '53', '69', '80', '88', '102', 
                        '110', '135', '137', '139', '143', '381', '383', '443', '464', '465', '587', 
                        '593', '636', '691', '902', '989', '990', '993', '995', '1025', '1194', '1337', 
                        '1589', '1725', '2082', '2083', '2483', '2484', '2967', '3074', '3306', '3724', '4664', 
                        '5432', '5900', '6665', '6669', '6881', '6999', '6970', '8086', '8087', '8222', '9100', 
                        '10000', '12345', '27374', '18006']
        
        try: 
       
            for port in common_ports :
       
                response = self.scan(server_addr,port)
       
                if response == 0 : 
       
                    self.open_port_list.append(port)
       
                if self.open_port_list  :
    
                    print(RED+f'Open port list = {self.open_port_list}'+END +WHITE +f'scannıng on process {port}\r'+END,end="")
        
                else :
                   
                    print(GREEN + f'{port} not open\r' + END,end ="")
                
                time.sleep(sleep_time)   
        
        except socket.error as error : 
           
            pass
        
        finally : 
            
            print(f'Open port list : {self.open_port_list}')
          
    def full_scan(self,server_addr,sleep_time=0) :
    
        print(GREEN + 
        ''' 
        This process can take a long time 
        [I]Full scan has been started...
            
         ''' + END )
        try :
            
            for port in self.port_list :
               
                response = self.scan(server_addr,port)
                
                if response == 0 : 
                    
                    self.open_port_list.append(port) 
                
                if self.open_port_list  :
                   
                    print(RED+f' Open port list = {self.open_port_list}'+END +WHITE +f'scanning on process {port}\r'+END,end="")
              
                else :
                  
                    print(GREEN + f'{port} not open\r' + END,end="")    
              
                time.sleep(sleep_time)
       
        except socket.error as error : 
           
            pass
        
        finally : 
            
            print(f'Open port list : {self.open_port_list}')
        
  
    def range_scan(self,server_addr,port_range=65535,sleep_time=0) : 
       
        print(RED + ' Thıs process take very long tıme ' + END )
       
        print(WHITE + '[I] Range scan has been started...' +END )
       
        port_range = int(port_range)
       
        try :
       
            for port in range(1,port_range+1):
       
                response = self.scan(server_addr,port)
       
                if response == 0 : 
       
                    print(RED + f'port open {port}' + END)
       
                    self.open_port_list.append(port)
                else : 
       
                    print(GREEN + f'{port} not open\r' + END,end="")
       
                time.sleep(sleep_time)
       
        except socket.error as error :
       
            pass
        
        finally :
       
            print(f'Open port list : {self.open_port_list}')
    
    
    def ping_scan(self) :
       
        print(RED + 'Alternative => "net_recon" ' + END)
                     
        gateway = conf.route.route('0.0.0.0')[2]
        
        print(RED+f'ROUTER ADDRESS  : {gateway}'+END)
        
        print(GREEN + ' [I] PING SCAN STARTED... ' + END) 
       
        gateway = gateway.split('.')
        
       
        while int(gateway[3]) <= 255 : 
           
            gateway = '.'.join(gateway)
            
            response = ping(gateway,timeout=0.5,count=3) 
            
            if response.success() :
               
                print(RED +f'{gateway} ON NETWORK ' + END)
               
                self.ping_true_list.append(gateway)
           
            gateway = gateway.split('.')
           
            gateway[3] = int(gateway[3])
           
            gateway[3] += 1
           
            gateway[3] = str(gateway[3])                
        
        self.net_show()
        
   
    def ICMP_scan(self) :
        
        print(WHITE +' [I] ICMP SCAN WITH SCAPY STARTED.....' + END )    
        
        for ip in range(1,256) :
        
            try:
        
                packet = IP(dst='192.168.1.' +str(ip),ttl=20)/ICMP()
        
                response = sr1(packet,timeout=1,verbose=False)
        
                if response.dst == packet.src: 
        
                    print(RED + 'ON NETWORK = ' + '192.168.1.'+str(ip) + END)
        
                    self.ping_true_list.append(response.src)
                    
            except AttributeError as NoneTypeError :
        
                print(GREEN + f'No response from 192.168.1.'+str(ip) + END)
        
        self.net_show()
            
   
    def net_recon(self) : 
       
        print(GREEN+'FASTEST ARP PING METHOD' +END)
       
        ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="192.168.1.0/24"), timeout=2,verbose=False)
       
        on_network = ans.summary(lambda s,r: r.sprintf("%Ether.src% %ARP.psrc%") )
       
        print(on_network)
        
    
    def stealth_scan(self,server_address,time_out) :
        print(GREEN +'[I] SYN Scan Started ........'+ END) 
       
        def probe_port(port):
            
            syn_packet = IP(dst=server_address)/TCP(dport=port,flags='S') 
           
            response = sr1(syn_packet,timeout=time_out,verbose=False)
           
            if response is not None :
               
                if response.haslayer(TCP) :    
                   
                    if response.getlayer(TCP).flags == 0x12:

                        print(RED + f'PORT OPEN {port}' + END)
                        
                        self.open_port_list.append(port)            
                    elif response.getlayer(TCP).flags == 0x14  :
                       
                        print(WHITE +f'port closed {port}'+ END)
                    
                    if response.haslayer(ICMP) : 
                    
                        if(int(response.getlayer(ICMP).type)==3 and int(response.getlayer(ICMP).code) in [1,2,3,9,10,13]):
                    
                            print(f'filtered port  = {port}')
                    
                            self.filtered_port_list.append(port)
            else :          
                
                print(WHITE +f'port closed  {port}'+ END)
        
        for port in self.port_list:
            
            probe_port(port)
        
        print('OPEN PORTS =',self.open_port_list)
        
        print('FILTERED PORTS = ',self.filtered_port_list)



    def tcp_ack_scan(self,server_address,time_out,seq_number) :
       
        print(RED + 'TCP ACK SCAN HELPS TO DETERMINE UNFILTERED PORTS'+ END)
        
        print(GREEN + 'ACK SCAN STARTED....'+ END)
        
        def probe_port(port) :   
            try :
                
                ack_packet = IP(dst=server_address)/TCP(dport=port,flags='A',seq=seq_number) 
               
                response = sr1(ack_packet,timeout=time_out,verbose=False)
                
                if response is None : 
                   
                    print(WHITE +f'PORT FILTERED {port}\r'+ END,end="")
               
                elif response is not None :
                   
                    if response.haslayer(TCP) :
                       
                        if  response.getlayer(TCP).flags == 'R' :
                           
                            print(RED +f'PORT UNFILTERED {port}'+END)
                            
                            self.unfiltered_port_list.append(port)
                    
                    if response.haslayer(ICMP) : 
                                
                                if(int(response.getlayer(ICMP).type)==3 and int(response.getlayer(ICMP).code) in [1,2,3,9,10,13]):
                                    
                                    print(RED + f'FILTERED PORT(ICMP ERROR)  = {port}' + END )
           
            except Exception as error : 
               
                pass
        
        for port in self.port_list :
            
            probe_port(port)
        
    
    def xmas_scan(self,server_address,time_out) : 
        
        print(GREEN + '[I] XMAS SCAN STARTED...' + END)
        try : 
            def probe_port(port):
            
                    xmas_packet = IP(dst=server_address)/TCP(dport=port,flags='FPU')
                
                    xmas_response = sr1(xmas_packet,timeout=time_out,verbose=False) 
                
                    if xmas_response is not None : 
                        
                        if xmas_response.haslayer(TCP) :
                            
                            if xmas_response.getlayer(TCP).flags == 'R' :
                                
                                print(WHITE +f'{port} CLOSED\r' + END,end="")
                    
                        elif xmas_response.haslayer(ICMP) :
                            
                            print(RED +f'{port} FILTERED '+END)

                    if xmas_response is None : 
                        print(RED +f'{port} OPEN/FILTERED'+ END)
                        
                        self.open_port_list.append(port)
        except : 
                
            print(RED +'Check url "wwww.example.com" '+ END)
        
        finally : 
            
            for port in self.port_list: 
            
                probe_port(port)     
            
            print(self.open_port_list)
    

    def zombie_scan(self,zombie,victim,zombie_port,time_out) :
       
        print(RED + 'MAKE SURE THAT THE MACHINE YOU HAVE TURNED INTO A ZOMBIE HAS THE LEAST AMOUNT OF TRAFFIC ON THE NETWORK ' + END)
       
        print(GREEN + ' [I] ZOMBIE SCAN STARTED...' + END)
        def zombie_probe(victim_port):
           
            evil_packet_start = IP(dst=zombie)/TCP(dport=zombie_port,flags='SA')     
           
            evil_response = sr1(evil_packet_start,timeout=time_out,verbose=False)
            
            try :
               
                if evil_response.haslayer(TCP) :        
                    
                    if evil_response.getlayer(TCP).flags == 'R'  :      
                      
                        evil_packet_victim = IP(dst=victim,src=zombie)/TCP(sport=zombie_port,dport=victim_port,flags='S')
                        
                        victim_start_response = sr1(evil_packet_victim,timeout=time_out,verbose=False)  
                       
                        evil_packet_zombie = IP(dst=zombie)/TCP(dport=zombie_port,flags='SA') 
                        
                        zombie_final_response = sr1(evil_packet_zombie,timeout=time_out,verbose=False)          
                        
                        if zombie_final_response is not None :
                            
                            if  zombie_final_response[IP].id ==  evil_response[IP].id + 2 :      
                               
                                self.open_port_list.append(victim_port)
                               
                                print( RED + f'port open {victim_port}' + END )
                                
                            else : 
                                print(WHITE + f'port closed or filtered {victim_port}\r' + END,end="")
                        else : 
                            print(RED +'from zombie couldnt receive the last packet' +END )
            except AttributeError as NoneTypeError : 
                
                print('CHECK ZOMBIE/ZOMBIE PORT/VICTIM ',NoneTypeError)
        
        for port in self.port_list :
            
            zombie_probe(port)

    
    def udp_scan(self,server_address,time_out):
       
        print(GREEN + '[I] UDP SCAN STARTED....'+END)
        
        def probe_udp(port):
           
            udp_packet = IP(dst=server_address)/UDP(dport=port) 
            
            response =sr1(udp_packet,timeout=time_out,verbose=False)
            
            if response is None : 
                
                print(RED + f'Port Closed/Filtered {port}'+ END)
                
                self.udp_closed_filtered_list.append(port)
            
            else :
                
                if response.haslayer(ICMP) :
                    
                    print(WHITE+f'PORT CLOSED {port}\r'+END,end="")
                
                elif response.haslayer(UDP):
                   
                    print(RED+f'PORT OPEN {port}'+END)
                   
                    self.udp_open_lists.append(port)
                
                else : 
                   
                    print(WHITE+f'FILTERED(ICMP UNREACHABLE) {port}'+END)

        for port in self.port_list :
            
            probe_udp(port)
        
        print('OPEN LIST :' ,self.udp_open_lists)
        
        print('CLOSED/FILTERED : ' ,self.udp_closed_filtered_list)    




if __name__ == '__main__': 
    
    scanner = PortScanner()

    parser = argparse.ArgumentParser(description='EYE PULSE CLI')
    
    ##########################METHODS########################
   
    parser.add_argument('-gIP','--get_ip',action='store_true')
    
    parser.add_argument('-serverC','--icmpsc',action='store_true')
    
    parser.add_argument('-spl','--spl',action='store_true',)
   
    parser.add_argument('-fS','--fast_scan',action='store_true')
    
    parser.add_argument('-fullS','--full_scan',action='store_true')
    
    parser.add_argument('-rS','--range_scan',action='store_true')
   
    parser.add_argument('-pS','--ping_scan',action='store_true')
    
    parser.add_argument('-icmpS','--icmp_scan',action='store_true')
    
    parser.add_argument('-nR','--net_recon',action='store_true')
    
    parser.add_argument('-sS','--stealth_scan',action='store_true')
    
    parser.add_argument('-tcpS','--tcp_ack_scan',action='store_true')
    
    parser.add_argument('-xmas','--xmas_scan',action='store_true')
    
    parser.add_argument('-zS','--zombie_scan',action='store_true')
    
    parser.add_argument('-uS','--udp_scan',action='store_true')
   
    ############################ARGSUMENTS########################
   
    parser.add_argument('-url','--url')
    
    parser.add_argument('-sA','--server_address')
    
    parser.add_argument('-sT','--sleep_time',type=float,default=0)
    
    parser.add_argument('-pR','--port_range',type=int,default=65535)
    
    parser.add_argument('-tO','--time_out',type=float,default=3)
    
    parser.add_argument('-sN','--seq_number',type=int,default=666)
    
    parser.add_argument('-zB','--zombie')
    
    parser.add_argument('-vC','--victim')
    
    parser.add_argument('-zP','--zombie_port',type=int,default=80)
    
    args = parser.parse_args() 
    
    
    if args.get_ip :
        
        scanner.get_ip(args.url)
        
    if args.icmpsc :
        
        scanner.server_control(args.server_address)
        
    if args.spl :
        
        scanner.show_ports()
    
    if args.fast_scan:
        scanner.fast_scan(args.server_address,args.sleep_time)
    
    if args.full_scan:
        
        scanner.full_scan(args.server_address,args.sleep_time)
    
    if args.range_scan :
        
        scanner.range_scan(args.server_address,args.port_range,args.sleep_time)
    
    if args.ping_scan:
        
        scanner.ping_scan()

    if args.icmp_scan:
       
        scanner.ICMP_scan()
    
    if args.net_recon:
        
        scanner.net_recon()
        
    if args.stealth_scan:
       
        scanner.stealth_scan(args.server_address,args.time_out)
    
    if args.tcp_ack_scan:
        
        scanner.tcp_ack_scan(args.server_address,args.time_out,args.seq_number)
    
    if args.xmas_scan:
        
        scanner.xmas_scan(args.server_address,args.time_out)
    
    if args.zombie_scan:
        
        scanner.zombie_scan(args.zombie,args.victim,args.zombie_port,args.time_out)
    
    if args.udp_scan:
        
        scanner.udp_scan(args.server_address,args.time_out)
    
    else : 
        scanner.usage()
