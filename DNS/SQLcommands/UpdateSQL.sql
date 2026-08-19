INSERT INTO dns_netbox_log
(
	event_time,
	LEVEL,
	ip_address,
	netbox_name,
	dns_name
)
VALUES
(
	NOW(),
	"Info",
	'10.1.130.200',
	'testvm',
	'test2vm'
);