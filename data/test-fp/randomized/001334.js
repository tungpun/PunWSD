(function(a,c){var b=a.customize;b.controlConstructor.site_logo=b.Control.extend({ready:function(){var d=this.container.find(".customize-control-title").data();this.l10n=d.l10n;this.mime=d.mime;this.$imgContainer=c("#customize-control-site_logo .current");this.$btnContainer=c("#customize-control-site_logo .actions");this.$img=c('<img class="site-logo-thumbnail" />').prependTo(this.$imgContainer);this.$placeholder=c("<span>"+this.l10n.placeholder+"</span>").prependTo(this.$imgContainer);this.$btnAdd=c('<button type="button" class="button new">'+this.l10n.upload+"</button>").prependTo(this.$btnContainer);this.$btnChange=c('<button type="button" class="button change">'+this.l10n.change+"</button>").prependTo(this.$btnContainer);this.$btnRemove=c('<button type="button" class="button remove">'+this.l10n.remove+"</button>").prependTo(this.$btnContainer);_.bindAll(this,"removeImg","upload","render","pick");this.$btnAdd.on("click",this.upload);this.$btnChange.on("click",this.upload);this.$btnRemove.on("click",this.removeImg);this.setting.bind("change",this.render);this.render()},upload:function(d){d.preventDefault();if(!this.frame){this.initFrame()}this.frame.open()},initFrame:function(){this.frame=a.media({title:this.l10n.choose,library:{type:this.mime},button:{text:this.l10n.set},multiple:false});this.frame.on("select",this.pick)},pick:function(){var d=this.frame.state().get("selection").first().toJSON();d=this.reduceMembers(d);this.setting(d)},reduceMembers:function(f){var e=["id","sizes","url"],d={};c.each(e,function(h,g){d[g]=f[g]});return d},render:function(){var d=this.setting();if(d&&d.url){this.$placeholder.hide();if(!d.sizes||!d.sizes.medium){this.$img.attr("src",d.url)}else{this.$img.attr("src",d.sizes.medium.url)}this.$img.show();this.$btnRemove.show();this.$btnChange.show();this.$btnAdd.hide()}else{this.$img.hide();this.$placeholder.show();this.$btnRemove.hide();this.$btnChange.hide();this.$btnAdd.show()}},removeImg:function(d){d.preventDefault();this.setting({url:"",id:0})}})})(this.wp,jQuery);