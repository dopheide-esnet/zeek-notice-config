zeek-notice-config
==================

This script enables easy customation of how notice actions are handled.
It's built to work with eZeekConfigurator, but that isn't required and can
be configured with a normal script.

Actions
-------
Notices can be configured with five different "actions", some of which
correspond to Zeek internal Notice::ACTION types.

	LOG - (default) Sets Notice::ACTION_LOG which logs to notice.log
	IGNORE - Ignores the notice and won't even log it.
	ALARM -Sets Notice::ACTION_ALARM which logs to notice-alarm.log
	PAGE - Sets Notice::ACTION_PAGE which you can handle how you see fit 
	BHR - Sets Notice::ACTION_BHR (not built in) which you can handle later.
	      This will only be set if Notice::ACTION_BHR has been previously defined.

Note, the current commonly used BHR scripts also set ACTION_BHR, but do not
process a black hole route based on that action existing.

There are no plans to support ACTION_EMAIL because we believe email is a
horrible way to alert enginners to a problem.

Each notice configuration element is built from an NC_Info record consisting
of up to four pieces of information:

	$src:  A set of source subnets that will be matched against the notice src.
	$src_in: A set of strings containing variable names whose contents  will be
	matched against the notice src.  For instance, you can match
	against "Site::local_nets" without having the duplicate the source
	nets.
	$note: A set of Notice::Types to match against.
	$action: A set of the above available notice-config actions

The notice_cfg itself is a vector of NC_Info.  This means it is ordered and
the first match will be processed for each notice.

An example configuration that will whitelist scan notices for local_nets
and then BHR the rest:

	module Notice;
	notice_cfg += NC_Info($src_in=set("Site::local_nets"),
			      $note=set(Scan::Address_Scan),
			      $action=set(IGNORE));
	notice_cfg += NC_Info($note=set(Scan::Address_Scan),
			      $action=set(LOG,BHR));

Since all of the items in NC_Info are sets, we can do the same thing with port
scans by modifying those same lines and not having to duplicate everything:

	module Notice;
	notice_cfg += NC_Info($src_in=set("Site::local_nets"),
	                      $note=set(Scan::Address_Scan, Scan::Port_Scan),
	                      $action=set(IGNORE));
	notice_cfg += NC_Info($note=set(Scan::Address_Scan, Scan::Port_Scan),
	                      $action=set(LOG,BHR));

If you also want to perform specific actions based on the Notice actions
you've set, a custom script can be written to handle those.  For example,
here is a skeleton for handling Notice::ACTION_PAGE:

	module Notice;
	export {
        	## Timeout for when() call when paging
        	option page_timeout: interval=3 sec;
	}
	
	hook Notice::policy(n: Notice::Info) &priority=5 {
		if(Notice::ACTION_PAGE in n$actions){
			when ( local result = Exec::run([$cmd=SOME_COMMAND])){
				print fmt("%s",result$stdout[0]);
			}timeout page_timeout{
				print(fmt("Couldn't page for some reason. %s",alert_type));
			}
		}
	}



