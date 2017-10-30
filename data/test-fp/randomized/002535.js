!function(a,b,c){"use strict";a.fn.WCBackboneModal=function(b){return this.each(function(){new a.WCBackboneModal(a(this),b)})},a.WCBackboneModal=function(b,c){var d=a.extend({},a.WCBackboneModal.defaultOptions,c);d.template&&new a.WCBackboneModal.View({target:d.template,string:d.variable})},a.WCBackboneModal.defaultOptions={template:"",variable:{}},a.WCBackboneModal.View=b.View.extend({tagName:"div",id:"wc-backbone-modal-dialog",_target:void 0,_string:void 0,events:{"click .modal-close":"closeButton","click #btn-ok":"addButton","touchstart #btn-ok":"addButton",keydown:"keyboardActions"},resizeContent:function(){var b=a(".wc-backbone-modal-content").find("article"),c=.75*a(window).height();b.css({"max-height":c+"px"})},initialize:function(b){var d=this;this._target=b.target,this._string=b.string,c.bindAll(this,"render"),this.render(),a(window).resize(function(){d.resizeContent()})},render:function(){var b=wp.template(this._target);this.$el.attr("tabindex","0").append(b(this._string)),a(document.body).css({overflow:"hidden"}).append(this.$el),this.resizeContent(),this.$el.focus(),a(document.body).trigger("init_tooltips"),a(document.body).trigger("wc_backbone_modal_loaded",this._target)},closeButton:function(b){b.preventDefault(),a(document.body).trigger("wc_backbone_modal_before_remove",this._target),this.undelegateEvents(),a(document).off("focusin"),a(document.body).css({overflow:"auto"}),this.remove(),a(document.body).trigger("wc_backbone_modal_removed",this._target)},addButton:function(b){a(document.body).trigger("wc_backbone_modal_response",[this._target,this.getFormData()]),this.closeButton(b)},getFormData:function(){var b={};return a(document.body).trigger("wc_backbone_modal_before_update",this._target),a.each(a("form",this.$el).serializeArray(),function(c,d){d.name.indexOf("[]")!==-1?(d.name=d.name.replace("[]",""),b[d.name]=a.makeArray(b[d.name]),b[d.name].push(d.value)):b[d.name]=d.value}),b},keyboardActions:function(a){var b=a.keyCode||a.which;13!==b||a.target.tagName&&("input"===a.target.tagName.toLowerCase()||"textarea"===a.target.tagName.toLowerCase())||this.addButton(a),27===b&&this.closeButton(a)}})}(jQuery,Backbone,_);