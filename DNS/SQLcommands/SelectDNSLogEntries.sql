SELECT *
	FROM dns_netbox_log 
	WHERE LEVEL != 'SKIP'
		AND DATE(event_time) = DATE(NOW());