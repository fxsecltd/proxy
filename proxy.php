<?php
/*
��������� http, http connect, socks5.
���������� �������� ���������� �������� �� HTTP-����������.
POST /update/ - ��������� ���������� ������ � �� ���������.
���� ������ � ������ ID �� ����������, �� �����������.
���� ����������, ��������� ������ �����������.
������, ���������� �� ����������� �������, ����� ����� ����������.
������ ���� �������, JSON:
{
   "access_control_entries": {
       "group1": "xxx.ru,yyy.com",
       "group2": ["qqq.ru", "www.com", "65.32.67.21"],
       "group3": "ttt.ru,eee.com,11.22.33.44"
   },
   "proxies": [
       {
           "id": 1,
           "internal_ip": "...",
           "external_ip": "...",
           "username": "...",
           "password": "...",
           "access_ips": ["33.33.22.12", "22.22.22.0/24"],
           "port_http": 12345,
           "port_socks5": 12346,
           "speed_limit": 100000,
           "allow": ["group1", "group2"],
           "ip_version": 4,
           **extra fields**
       },
       {
           "id": 2,
           "internal_ip": "...",
           "external_ip": "...",
           "username": "...",
           "password": "...",
           "port_http": 12347,
           "port_socks5": 12348,
           "speed_limit": null,
           "disallow": ["group3"],
           "ip_version": 6,
           **extra fields**
       }
   ]
}
 
access_control_entries - ������� ���_������:��������
�������� ����� ���� �������, ��� ����� ��������� �������, ���� �������

proxies - ������ ������
	internal_ip, external_ip - IP ������
port_http, port_socks5 - �����, ������� ���������� ������������ ��� ������
username, password - �����:������, ����� ���� ����������� ��� ��������� ������
access_ips - ������ IP (��� CIDR) � ������� �������� ������ � ������. ���� �������� IP, �����:������ ��� ����� ��������. ���� �����:������ �� �������� ��� �������� ��������, � IP ������������ ����������, �� ������ ��� ����� ������ ��������.  
speed_limit - ����� �������� � ������, ���� ������
allow - ������ �������� ����� �� access_control_entries. ���� �������, ������ ����� ������ �������� ������ �� ���� ������.
disallow - ������ �������� ����� �� access_control_entries. ���� �������, ������ ����� ������ �� ���� ������ ����������.
ip_version - ���� ����� 6, �� internal_ip ����� IPv4, � external_ip IPv6. ��� ���� ������ ���� �������� ������ IPv6-�����. � 3proxy ��� ������� ��� "Only resolve IPv6 addresses. IPv4 addresses are packed in IPv6 in IPV6_V6ONLY compatible way."

���� access_ips, speed_limit, allow, disallow ����� ������������� ���� ���� null.

��� ������� ������ ������������. 
����� ����������� ��������� ����� ��� ������ �����, � ����� ����������� ������ �� � stdout.
� ����� ������ ����:
		- ����
	- ID ������
	- http ��� socks5
	- IP ������������
	- IP ������
	- IP ���������� �������
	- URL ���� ����

����� ����������� ��������� ���� ns-�������.
���������� ������� ������ ����������� � json ���� � ������� 
{
   "2021-07-27": {
     "proxy_id": [
       bytes_in,
       bytes_out
     ],
     "proxy_id": [
       bytes_in,
       bytes_out
     ]
   }
}
���������� ������� ���������� �� 2 ���, ������ ��� �������.
���� � UTC.
��� ����������� ������� ������� ������������ �� �������� � �����.
������ ����������� ��� � ��������� �����.

������������� ����������� ����� ������������ ������������� �������� ����� ��������� ������, ���� ����� ��������.
�� ����� ����� ����� ���� ����� ������ IP
*/

if(isset($_POST['conf']))
{
    $obj = json_decode($_REQUEST['conf']);
    $acl = $obj->{'access_control_entries'};
    for($i=0;$i<count($acl);$i++)
    {
        echo $acl[$i][0];
        echo $acl[$i][1];
    }
    $lst = $obj->{'proxies'};
    for($i=0;$i<count($lst);$i++)
    {
        echo $acl[$i][0];//id
        echo $acl[$i][1];//internal_ip
        echo $acl[$i][2];//external_ip
        echo $acl[$i][3];//username
        echo $acl[$i][4];//password
        echo $acl[$i][5];//access_ips[]
        echo $acl[$i][6];//port_http
        echo $acl[$i][7];//port_socks5
        echo $acl[$i][8];//speed_limit
        echo $acl[$i][9];//allow[]
        echo $acl[$i][10];//ip_version
        echo $acl[$i][11];//extra_fields[]
    }
    $stats = array();
    for($i=0;$i<count($proxylist);$i++)
    {
        $stats.push(array($proxylist[$i].id,array($proxylist[$i].in,$proxylist[$i].out)));    
    }
    $jsonstat = json_encode(array($datestring,$stats);
}
?>