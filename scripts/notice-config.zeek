##! Notice policy configuration
##!

@load base/frameworks/notice
@load base/utils/site
#@load site/bhr-bro

module Notice;

export {
	## Supported notice actions, note that email actions aren't supported because Sam hates email
    ## Existence of IGNORE will trump all other actions and the notice will not be logged
	type NC_actions: enum { LOG, IGNORE, BHR, ALARM, PAGE };

	## Notice Config record type
	type NC_Info: record {
		## matches against the $src field of Notice::Info if it exists
		src: set[subnet] &optional;
		## matches against a variable, typically something like Site::local_nets
		src_in: set[string] &optional;
		## The notice type
		note: set[Notice::Type] &optional;
		## Set of action to take for this notice
		action: set[NC_actions] &default=set(LOG);
	};

	## Vector of Notice Configuration policies
	option notice_cfg: vector of NC_Info = {};

	global process_notice: function(n: Notice::Info): set[Notice::Action];
	global process_actions: function(new_actions: set[Notice::Action],
									action_set: set[Notice::Action]): set[Notice::Action];
}

## This function will process actions by setting up the notice's action_set
## but also firing off BHR or Alarm/Pages as necessary
## OR.. should those be handled by a separate script since other sites operate differently?

function test_membership(ip: addr, names: set[string]): bool {
	local match: bool=F;

	for (name in names){
		local n = lookup_ID(name);

		if ( type_name(n) != "set[subnet]" ){
			Reporter::warning(fmt("Looked up %s and expected set[subnet], got '%s'.", name, type_name(n)));
			return F;
		}

		if(ip in n as set[subnet]){
			return T;
		}
	}
	return F;
}


function process_actions(new_actions: set[Notice::Action], action_set: set[Notice::Action]): set[Notice::Action]{

	if(Notice::IGNORE in new_actions){
		## Clear the action set, don't even LOG.
		## Use this sparingly because it's going to throw off all of your metrics
		## If you're going to totally ignore an action, why are you running that policy?
		## More likely used to IGNORE your vulnerability scanners
		action_set = set();
		return action_set;
	}
	@ifdef ( Notice::ACTION_BHR )
	if(Notice::BHR in new_actions){
		add action_set[Notice::ACTION_BHR];
		action_set = set();
	}
	@endif

	# Adding LOG is most likely redundant with the notice framework
	if(Notice::LOG in new_actions){
		add action_set[Notice::ACTION_LOG];
	}
	if(Notice::ALARM in new_actions){
		add action_set[Notice::ACTION_ALARM];
	}
	if(Notice::PAGE in new_actions){
		add action_set[Notice::ACTION_PAGE];
	}

	return action_set;
}


function process_notice(n: Notice::Info): set[Notice::Action]{

	##! All existing conditions must match except src/src_in which is either/or

	for(i in notice_cfg){
		local nc = notice_cfg[i];  # just makes the rest a little neater to look at

		if(nc?$note && ! nc?$src && ! nc?$src_in){
			if(n$note in nc$note){
				n$actions = process_actions(nc$action,n$actions);
				return n$actions;
			}
		}

		if(n?$src && (nc?$src || nc?$src_in) && ! nc?$note){
			if((nc?$src && n$src in nc$src) || (nc?$src_in && test_membership(n$src,nc$src_in))){
					n$actions = process_actions(nc$action,n$actions);
					return n$actions;
			}
		}

		if(nc?$note && n?$src && (nc?$src || nc?$src_in)){
			if(n$note in nc$note){
				if((nc?$src && n$src in nc$src) || (nc?$src_in && test_membership(n$src,nc$src_in))){
					n$actions = process_actions(nc$action,n$actions);
					return n$actions;
				}
			}
		}
	}

	##! just stay with default actions.
	return n$actions;
}

##! priority is set to hit after the default ACTION::LOG is set but before the logs are written
##! by the notice framework
hook Notice::policy(n: Notice::Info) &priority=5 {

##! why doesn't this syntax work?  []'s instead of NC_Into()
##!	notice_cfg += [$note=Notice::Debug_Notice2, $action=set(LOG, PAGE)];

	print("Notice config");
	local n_actions: set[Notice::Action];

	n$actions = process_notice(n);

}

