jQuery(function(a){function b(){a("#tiptip_holder").removeAttr("style"),a("#tiptip_arrow").removeAttr("style"),a(".tips").tipTip({attribute:"data-tip",fadeIn:50,fadeOut:50,delay:200})}b(),a("#titlediv").find("#title").keyup(function(b){var c=b.keyCode||b.which;if("9"===c&&a("#woocommerce-coupon-description").length>0)return b.stopPropagation(),a("#woocommerce-coupon-description").focus(),!1}),a(".wc-metaboxes-wrapper").on("click",".wc-metabox > h3",function(){a(this).parent(".wc-metabox").toggleClass("closed").toggleClass("open")}),a(document.body).on("wc-init-tabbed-panels",function(){a("ul.wc-tabs").show(),a("ul.wc-tabs a").click(function(b){b.preventDefault();var c=a(this).closest("div.panel-wrap");a("ul.wc-tabs li",c).removeClass("active"),a(this).parent().addClass("active"),a("div.panel",c).hide(),a(a(this).attr("href")).show()}),a("div.panel-wrap").each(function(){a(this).find("ul.wc-tabs li").eq(0).find("a").click()})}).trigger("wc-init-tabbed-panels"),a(document.body).on("wc-init-datepickers",function(){a(".date-picker-field, .date-picker").datepicker({dateFormat:"yy-mm-dd",numberOfMonths:1,showButtonPanel:!0})}).trigger("wc-init-datepickers"),a(".wc-metaboxes-wrapper").on("click",".wc-metabox h3",function(b){a(b.target).filter(":input, option, .sort").length||a(this).next(".wc-metabox-content").stop().slideToggle()}).on("click",".expand_all",function(){return a(this).closest(".wc-metaboxes-wrapper").find(".wc-metabox > .wc-metabox-content").show(),!1}).on("click",".close_all",function(){return a(this).closest(".wc-metaboxes-wrapper").find(".wc-metabox > .wc-metabox-content").hide(),!1}),a(".wc-metabox.closed").each(function(){a(this).find(".wc-metabox-content").hide()})});