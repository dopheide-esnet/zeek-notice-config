# @TEST-EXEC: zeek -C -r $TRACES/ntp-monlist.pcap ../../../scripts %INPUT
# @TEST-EXEC: zeek-cut msg note < notice.log > notice.tmp && mv notice.tmp notice.log
# @TEST-EXEC: btest-diff notice.log
# @TEST-EXEC: zeek-cut msg note < notice_alarm.log > notice_alarm.tmp && mv notice_alarm.tmp notice_alarm.log
# @TEST-EXEC: btest-diff notice_alarm.log

@load base/frameworks/notice
@load base/utils/site

module Notice;

export {
	redef Site::neighbor_nets += { 10.1.0.0/24 };
	redef enum Notice::Action += {
		Notice::ACTION_BHR
	};
}

@load ./notice-config.zeek

redef enum Notice::Type += {
	Debug_Notice,
	Debug_Notice2,
	Debug_Notice3,
	Debug_Notice4,
	Debug_Notice5
};


event zeek_init(){
	notice_cfg += NC_Info($src=set(10.2.0.0/24), $note=set(Notice::Debug_Notice), $action=set(LOG, ALARM));
	notice_cfg += NC_Info($note=set(Notice::Debug_Notice2), $action=set(LOG, ALARM, PAGE));
	notice_cfg += NC_Info($src=set(10.3.0.0/24), $note=set(Notice::Debug_Notice3), $action=set(IGNORE));

#	notice_cfg += NC_Info($src_in=set("Site::neighbor_nets"), $action=set(IGNORE));

	notice_cfg += NC_Info($src_in=set("Site::neighbor_nets"), $note=set(Notice::Debug_Notice4), $action=set(LOG,ALARM));

	notice_cfg += NC_Info($note=set(Notice::Debug_Notice4), $action=set(BHR));
	notice_cfg += NC_Info($src=set(10.3.0.0/24), $action=set(LOG));


	# save these for test cases
	NOTICE([$note=Notice::Debug_Notice, $msg=fmt("Should LOG,ALARM"), $src=10.2.0.1]);
	NOTICE([$note=Notice::Debug_Notice2, $msg=fmt("Should LOG,PAGE")]);
	NOTICE([$note=Notice::Debug_Notice3, $msg=fmt("debug notice to be ignored"), $src=10.3.0.1]);
	NOTICE([$note=Notice::Debug_Notice4, $msg=fmt("Should not BHR due to neighbor_nets"), $src=10.1.0.1]);
	NOTICE([$note=Notice::Debug_Notice4, $msg=fmt("Should BHR"), $src=192.168.0.1]);
	NOTICE([$note=Notice::Debug_Notice5, $msg=fmt("Should just LOG"), $src=10.3.0.1]);

}
