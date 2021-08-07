<?php
/*
Поддержка http, http connect, socks5.
Управление сервером происходит локально по HTTP-интерфейсу.
POST /update/ - обновляет запущенные прокси и их параметры.
Если прокси с данным ID не существует, он запускается.
Если существует, параметры прокси обновляются.
Записи, отвечающие за ограничение доступа, также могут измениться.
формат тела запроса, JSON:
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
           "disallow": ["group1", "group2"],
           "ip_version": 4,
           **extra fields**
       },
       {
           "id": 2,
           "internal_ip": "...",
           "external_ip": "...",
           "username": "...",
           "password": "...",
           "access_ips": ["33.33.22.12", "22.22.22.0/24"],
           "port_http": 12347,
           "port_socks5": 12348,
           "speed_limit": null,
           "allow": ["group3"],
           "disallow": ["group3"],
           "ip_version": 6,
           **extra fields**
       }
   ]
}
 
access_control_entries - словарь имя_группы:значение
значение может быть строкой, где хосты разделены запятой, либо списком

proxies - список прокси
	internal_ip, external_ip - IP прокси
port_http, port_socks5 - порты, которые необходимо использовать для прокси
username, password - логин:пароль, могут быть одинаковыми для множества прокси
access_ips - список IP (или CIDR) с которых разрешен доступ к прокси. Если переданы IP, логин:пароль все равно работает. Если логин:пароль не переданы или переданы неверные, а IP пользователя правильный, то прокси все равно должен работать.  
speed_limit - лимит скорости в байтах, если указан
allow - список названий групп из access_control_entries. Если указано, доступ через прокси возможен только до этих хостов.
disallow - список названий групп из access_control_entries. Если указано, доступ через прокси до этих хостов невозможен.
ip_version - Если равно 6, то internal_ip будет IPv4, а external_ip IPv6. При этом должны быть доступны только IPv6-сайты. В 3proxy это описано как "Only resolve IPv6 addresses. IPv4 addresses are packed in IPv6 in IPV6_V6ONLY compatible way."

Поля access_ips, speed_limit, allow, disallow могут отсутствовать либо быть null.

Все запросы должны логироваться. 
Нужна возможность указывать место для записи логов, а также возможность писать их в stdout.
В логах должны быть:
		- Дата
	- ID прокси
	- http или socks5
	- IP пользователя
	- IP Прокси
	- IP удаленного сервера
	- URL если есть

Нужна возможность указывать свои ns-серверы.
Статистика трафика должна сохраняться в json файл в формате 
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
Достаточно хранить статистику за 2 дня, старые дни удалять.
Дата в UTC.
При перезапуске сервера подсчет продолжается со значений в файле.
Должен обновляться раз в несколько минут.

Предусмотреть возможность более равномерного распределения скорости между активными прокси, если такое возможно.
На одном порту может быть много разных IP

СТРУКТУРА ТАБЛИЦ БАЗЫ ДАННЫХ

Для хранения параметров отдельных инстанций прокси серверов используется таблица servers 
имеющая следующие поля:
id INTEGER NOT NULL AITOINCREMENT PRIMARY_KEY
external_id INTEGER NOT NULL
internal_ip VARCHAR(24) NOT NULL
external_ip VARCHAR(24) NOT NULL
username VARCHAR(255) NOT NULL
password VARCHAR(255) NOT NULL
port_http INTEGER NOT NULL
port_socks5 INTEGER NOT NULL
speed_limit INTEGER NOT NULL
disallow TEXT NOT NULL
ip_version INTEGER NOT NULL

Для хранения параметров групп доступа для отдельных инстанций прокси серверов используется таблица acls 
имеющая следующие поля:
id INTEGER NOT NULL AITOINCREMENT PRIMARY_KEY
external_id VARCHAR(255) NOT NULL
textrule VARCHAR(255) NOT NULL

Для хранение параметров отдельных сессий инстанций прокси серверов используется таблица sessions
id INTEGER NOT NULL AITOINCREMENT PRIMARY_KEY
source_ip VARCHAR(24) NOT NULL
destination VARCHAR(24) NOT NULL
serverid INTEGER NOT NULL
tmstamp INTEGER NOT NULL
portused INTEGER NOT NULL
bytesin INTEGER NOT NULL
bytesout INTEGER NOT NULL

Для хранение параметров отдельных инстанций прокси серверов используется таблица history
id INTEGER NOT NULL AITOINCREMENT PRIMARY_KEY
serverid INTEGER NOT NULL
tmlength INTEGER NOT NULL
portused INTEGER NOT NULL
bytesin INTEGER NOT NULL
bytesout INTEGER NOT NULL


Для хранения 
*/

if(isset($_POST['conf']))
{
  $db = new SQLite3('/usr/var/www/proxy.db');
  $db->query("CREATE TABLE IF NOT EXIST servers(
  	id INTEGER NOT NULL AITOINCREMENT PRIMARY_KEY,
  	external_id INTEGER NOT NULL,
	internal_ip VARCHAR(24) NOT NULL,
  	external_ip VARCHAR(24) NOT NULL,
  	username VARCHAR(255) NOT NULL,
  	password VARCHAR(255) NOT NULL,
  	access_ips TEXT NOT NULL,
  	port_http INTEGER NOT NULL,
  	port_socks5 INTEGER NOT NULL,
  	speed_limit INTEGER NOT NULL,
  	allow TEXT NOT NULL,
  	disallow TEXT NOT NULL,
  	ip_version INTEGER NOT NULL,)");
  $db->query("CREATE TABLE IF NOT EXIST acls(
  	id INTEGER NOT NULL AITOINCREMENT PRIMARY_KEY,
  	external_id VARCHAR(255),
	textrule VARCHAR(255) NOT NULL,)");
  $db->query("CREATE TABLE IF NOT EXIST sessions(
  	id INTEGER NOT NULL AITOINCREMENT PRIMARY_KEY,
	source_ip VARCHAR(24) NOT NULL,
	destination VARCHAR(255) NOT NULL,
	serverid INTEGER NOT NULL
	tmstamp INTEGER NOT NULL
	portused INTEGER NOT NULL
	bytesin INTEGER NOT NULL
	bytesout INTEGER NOT NULL,)");
  $db->query("CREATE TABLE IF NOT EXIST history(
  	id INTEGER NOT NULL AITOINCREMENT PRIMARY_KEY,
	serverid INTEGER NOT NULL,
	tmlength INTEGER NOT NULL,
	portused INTEGER NOT NULL,
	bytesin INTEGER NOT NULL,
	bytesout INTEGER NOT NULL,)");
  $obj = json_decode($_REQUEST['conf']);
  $acl = $obj->{'access_control_entries'};
  for($i=0;$i<count($acl);$i++)
  {
	$db->query("DELETE FROM acls");  
	$db->query("INSERT INTO acls(external_id,textrule) values(
		'".$acl[$i][0]."',//external_id, string
		'".$acl[$i][1]."',//textrule, string
		)");  
  }
  $lst = $obj->{'proxies'};
  for($i=0;$i<count($lst);$i++)
  {
	$db->query("DELETE FROM servers");  
	$db->query("INSERT INTO servers(external_id,internal_ip,external_ip,username,password,port_http,port_socks5,speed_limit,disallow,ip_version) values(
		 ".$acl[$i][0].", //external_id, int
		'".$acl[$i][1]."',//internal_ip, string
		'".$acl[$i][2]."',//external_ip, string
		'".$acl[$i][3]."',//username, string
		'".$acl[$i][4]."',//password, string
		'".$acl[$i][5]."',//access_ips, string
		 ".$acl[$i][6].", //port_http, int
		 ".$acl[$i][7].", //port_socks5, int
		 ".$acl[$i][8].", //speed_limit, int
		'".$acl[$i][9]."',//allow, string
		'".$acl[$i][9]."',//disallow, string
		 ".$acl[$i][10]." //ip_version, int
		)");  
  }
  $stats = array();
  $result = $db->query("SELECT source_ip,destination,serverid,tmstamp,portused,bytesin,bytesout FROM sessions ORDER BY tmstamp DESC");
  $proxylist = array();
  while($data = $result->fetchArray(SQLITE3_ASSOC))
  {
     $proxylist[] = $data;
  }
  for($i=0;$i<count($proxylist);$i++)
  {
     $stats[]=array($proxylist[$i].serverid,array($proxylist[$i].bytesin,$proxylist[$i].bytesout)));    
  }
  $jsonstat = json_encode(array($datestring,$stats);
  echo $jsonstat;
}
?>
