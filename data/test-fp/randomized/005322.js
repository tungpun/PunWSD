!function a(b,c,d){function e(g,h){if(!c[g]){if(!b[g]){var i="function"==typeof require&&require;if(!h&&i)return i(g,!0);if(f)return f(g,!0);var j=new Error("Cannot find module '"+g+"'");throw j.code="MODULE_NOT_FOUND",j}var k=c[g]={exports:{}};b[g][0].call(k.exports,function(a){var c=b[g][1][a];return e(c?c:a)},k,k.exports,a,b,c,d)}return c[g].exports}for(var f="function"==typeof require&&require,g=0;g<d.length;g++)e(d[g]);return e}({1:[function(a,b,c){var d,e=wp.media.view.l10n;d=wp.media.controller.State.extend({defaults:{id:"edit-attachment",title:e.attachmentDetails,content:"edit-metadata",menu:!1,toolbar:!1,router:!1}}),b.exports=d},{}],2:[function(a,b,c){var d=wp.media;d.controller.EditAttachmentMetadata=a("./controllers/edit-attachment-metadata.js"),d.view.MediaFrame.Manage=a("./views/frame/manage.js"),d.view.Attachment.Details.TwoColumn=a("./views/attachment/details-two-column.js"),d.view.MediaFrame.Manage.Router=a("./routers/manage.js"),d.view.EditImage.Details=a("./views/edit-image-details.js"),d.view.MediaFrame.EditAttachments=a("./views/frame/edit-attachments.js"),d.view.SelectModeToggleButton=a("./views/button/select-mode-toggle.js"),d.view.DeleteSelectedButton=a("./views/button/delete-selected.js"),d.view.DeleteSelectedPermanentlyButton=a("./views/button/delete-selected-permanently.js")},{"./controllers/edit-attachment-metadata.js":1,"./routers/manage.js":3,"./views/attachment/details-two-column.js":4,"./views/button/delete-selected-permanently.js":5,"./views/button/delete-selected.js":6,"./views/button/select-mode-toggle.js":7,"./views/edit-image-details.js":8,"./views/frame/edit-attachments.js":9,"./views/frame/manage.js":10}],3:[function(a,b,c){var d=Backbone.Router.extend({routes:{"upload.php?item=:slug":"showItem","upload.php?search=:query":"search"},baseUrl:function(a){return"upload.php"+a},search:function(a){jQuery("#media-search-input").val(a).trigger("input")},showItem:function(a){var b,c=wp.media,d=c.frame.state().get("library");b=d.findWhere({id:parseInt(a,10)}),b?c.frame.trigger("edit:attachment",b):(b=c.attachment(a),c.frame.listenTo(b,"change",function(a){c.frame.stopListening(b),c.frame.trigger("edit:attachment",a)}),b.fetch())}});b.exports=d},{}],4:[function(a,b,c){var d,e=wp.media.view.Attachment.Details;d=e.extend({template:wp.template("attachment-details-two-column"),editAttachment:function(a){a.preventDefault(),this.controller.content.mode("edit-image")},toggleSelectionHandler:function(){},render:function(){e.prototype.render.apply(this,arguments),wp.media.mixin.removeAllPlayers(),this.$("audio, video").each(function(a,b){var c=wp.media.view.MediaDetails.prepareSrc(b);new window.MediaElementPlayer(c,wp.media.mixin.mejsSettings)})}}),b.exports=d},{}],5:[function(a,b,c){var d,e=wp.media.view.Button,f=wp.media.view.DeleteSelectedButton;d=f.extend({initialize:function(){f.prototype.initialize.apply(this,arguments),this.controller.on("select:activate",this.selectActivate,this),this.controller.on("select:deactivate",this.selectDeactivate,this)},filterChange:function(a){this.canShow="trash"===a.get("status")},selectActivate:function(){this.toggleDisabled(),this.$el.toggleClass("hidden",!this.canShow)},selectDeactivate:function(){this.toggleDisabled(),this.$el.addClass("hidden")},render:function(){return e.prototype.render.apply(this,arguments),this.selectActivate(),this}}),b.exports=d},{}],6:[function(a,b,c){var d,e=wp.media.view.Button,f=wp.media.view.l10n;d=e.extend({initialize:function(){e.prototype.initialize.apply(this,arguments),this.options.filters&&this.options.filters.model.on("change",this.filterChange,this),this.controller.on("selection:toggle",this.toggleDisabled,this)},filterChange:function(a){"trash"===a.get("status")?this.model.set("text",f.untrashSelected):wp.media.view.settings.mediaTrash?this.model.set("text",f.trashSelected):this.model.set("text",f.deleteSelected)},toggleDisabled:function(){this.model.set("disabled",!this.controller.state().get("selection").length)},render:function(){return e.prototype.render.apply(this,arguments),this.controller.isModeActive("select")?this.$el.addClass("delete-selected-button"):this.$el.addClass("delete-selected-button hidden"),this.toggleDisabled(),this}}),b.exports=d},{}],7:[function(a,b,c){var d,e=wp.media.view.Button,f=wp.media.view.l10n;d=e.extend({initialize:function(){_.defaults(this.options,{size:""}),e.prototype.initialize.apply(this,arguments),this.controller.on("select:activate select:deactivate",this.toggleBulkEditHandler,this),this.controller.on("selection:action:done",this.back,this)},back:function(){this.controller.deactivateMode("select").activateMode("edit")},click:function(){e.prototype.click.apply(this,arguments),this.controller.isModeActive("select")?this.back():this.controller.deactivateMode("edit").activateMode("select")},render:function(){return e.prototype.render.apply(this,arguments),this.$el.addClass("select-mode-toggle-button"),this},toggleBulkEditHandler:function(){var a,b=this.controller.content.get().toolbar;a=b.$(".media-toolbar-secondary > *, .media-toolbar-primary > *"),this.controller.isModeActive("select")?(this.model.set({size:"large",text:f.cancelSelection}),a.not(".spinner, .media-button").hide(),this.$el.show(),b.$(".delete-selected-button").removeClass("hidden")):(this.model.set({size:"",text:f.bulkSelect}),this.controller.content.get().$el.removeClass("fixed"),b.$el.css("width",""),b.$(".delete-selected-button").addClass("hidden"),a.not(".media-button").show(),this.controller.state().get("selection").reset())}}),b.exports=d},{}],8:[function(a,b,c){var d,e=wp.media.View,f=wp.media.view.EditImage;d=f.extend({initialize:function(a){this.editor=window.imageEdit,this.frame=a.frame,this.controller=a.controller,e.prototype.initialize.apply(this,arguments)},back:function(){this.frame.content.mode("edit-metadata")},save:function(){this.model.fetch().done(_.bind(function(){this.frame.content.mode("edit-metadata")},this))}}),b.exports=d},{}],9:[function(a,b,c){var d,e=wp.media.view.Frame,f=wp.media.view.MediaFrame,g=jQuery;d=f.extend({className:"edit-attachment-frame",template:wp.template("edit-attachment-frame"),regions:["title","content"],events:{"click .left":"previousMediaItem","click .right":"nextMediaItem"},initialize:function(){e.prototype.initialize.apply(this,arguments),_.defaults(this.options,{modal:!0,state:"edit-attachment"}),this.controller=this.options.controller,this.gridRouter=this.controller.gridRouter,this.library=this.options.library,this.options.model&&(this.model=this.options.model),this.bindHandlers(),this.createStates(),this.createModal(),this.title.mode("default"),this.toggleNav()},bindHandlers:function(){this.on("title:create:default",this.createTitle,this),this.listenTo(this.model,"change:status destroy",this.close,this),this.on("content:create:edit-metadata",this.editMetadataMode,this),this.on("content:create:edit-image",this.editImageMode,this),this.on("content:render:edit-image",this.editImageModeRender,this),this.on("close",this.detach)},createModal:function(){this.options.modal&&(this.modal=new wp.media.view.Modal({controller:this,title:this.options.title}),this.modal.on("open",_.bind(function(){g("body").on("keydown.media-modal",_.bind(this.keyEvent,this))},this)),this.modal.on("close",_.bind(function(){this.modal.remove(),g("body").off("keydown.media-modal"),g('li.attachment[data-id="'+this.model.get("id")+'"]').focus(),this.resetRoute()},this)),this.modal.content(this),this.modal.open())},createStates:function(){this.states.add([new wp.media.controller.EditAttachmentMetadata({model:this.model})])},editMetadataMode:function(a){a.view=new wp.media.view.Attachment.Details.TwoColumn({controller:this,model:this.model}),a.view.views.set(".attachment-compat",new wp.media.view.AttachmentCompat({controller:this,model:this.model})),this.model&&this.gridRouter.navigate(this.gridRouter.baseUrl("?item="+this.model.id))},editImageMode:function(a){var b=new wp.media.controller.EditImage({model:this.model,frame:this});b._toolbar=function(){},b._router=function(){},b._menu=function(){},a.view=new wp.media.view.EditImage.Details({model:this.model,frame:this,controller:b})},editImageModeRender:function(a){a.on("ready",a.loadEditor)},toggleNav:function(){this.$(".left").toggleClass("disabled",!this.hasPrevious()),this.$(".right").toggleClass("disabled",!this.hasNext())},rerender:function(){"edit-metadata"!==this.content.mode()?this.content.mode("edit-metadata"):this.content.render(),this.toggleNav()},previousMediaItem:function(){return this.hasPrevious()?(this.model=this.library.at(this.getCurrentIndex()-1),this.rerender(),void this.$(".left").focus()):void this.$(".left").blur()},nextMediaItem:function(){return this.hasNext()?(this.model=this.library.at(this.getCurrentIndex()+1),this.rerender(),void this.$(".right").focus()):void this.$(".right").blur()},getCurrentIndex:function(){return this.library.indexOf(this.model)},hasNext:function(){return this.getCurrentIndex()+1<this.library.length},hasPrevious:function(){return this.getCurrentIndex()-1>-1},keyEvent:function(a){("INPUT"!==a.target.nodeName&&"TEXTAREA"!==a.target.nodeName||a.target.readOnly||a.target.disabled)&&(39===a.keyCode&&this.nextMediaItem(),37===a.keyCode&&this.previousMediaItem())},resetRoute:function(){this.gridRouter.navigate(this.gridRouter.baseUrl(""))}}),b.exports=d},{}],10:[function(a,b,c){var d,e=wp.media.view.MediaFrame,f=wp.media.controller.Library,g=Backbone.$;d=e.extend({initialize:function(){_.defaults(this.options,{title:"",modal:!1,selection:[],library:{},multiple:"add",state:"library",uploader:!0,mode:["grid","edit"]}),this.$body=g(document.body),this.$window=g(window),this.$adminBar=g("#wpadminbar"),this.$window.on("scroll resize",_.debounce(_.bind(this.fixPosition,this),15)),g(document).on("click",".page-title-action",_.bind(this.addNewClickHandler,this)),this.$el.addClass("wp-core-ui"),!wp.Uploader.limitExceeded&&wp.Uploader.browser.supported||(this.options.uploader=!1),this.options.uploader&&(this.uploader=new wp.media.view.UploaderWindow({controller:this,uploader:{dropzone:document.body,container:document.body}}).render(),this.uploader.ready(),g("body").append(this.uploader.el),this.options.uploader=!1),this.gridRouter=new wp.media.view.MediaFrame.Manage.Router,e.prototype.initialize.apply(this,arguments),this.$el.appendTo(this.options.container),this.createStates(),this.bindRegionModeHandlers(),this.render(),this.bindSearchHandler()},bindSearchHandler:function(){var a=this.$("#media-search-input"),b=this.options.container.data("search"),c=this.browserView.toolbar.get("search").$el,d=this.$(".view-list"),e=_.debounce(function(a){var b=g(a.currentTarget).val(),c="";b&&(c+="?search="+b),this.gridRouter.navigate(this.gridRouter.baseUrl(c))},1e3);a.on("input",_.bind(e,this)),c.val(b).trigger("input"),this.gridRouter.on("route:search",function(){var a=window.location.href;a.indexOf("mode=")>-1?a=a.replace(/mode=[^&]+/g,"mode=list"):a+=a.indexOf("?")>-1?"&mode=list":"?mode=list",a=a.replace("search=","s="),d.prop("href",a)})},createStates:function(){var a=this.options;this.options.states||this.states.add([new f({library:wp.media.query(a.library),multiple:a.multiple,title:a.title,content:"browse",toolbar:"select",contentUserSetting:!1,filterable:"all",autoSelect:!1})])},bindRegionModeHandlers:function(){this.on("content:create:browse",this.browseContent,this),this.on("edit:attachment",this.openEditAttachmentModal,this),this.on("select:activate",this.bindKeydown,this),this.on("select:deactivate",this.unbindKeydown,this)},handleKeydown:function(a){27===a.which&&(a.preventDefault(),this.deactivateMode("select").activateMode("edit"))},bindKeydown:function(){this.$body.on("keydown.select",_.bind(this.handleKeydown,this))},unbindKeydown:function(){this.$body.off("keydown.select")},fixPosition:function(){var a,b;this.isModeActive("select")&&(a=this.$(".attachments-browser"),b=a.find(".media-toolbar"),a.offset().top+16<this.$window.scrollTop()+this.$adminBar.height()?(a.addClass("fixed"),b.css("width",a.width()+"px")):(a.removeClass("fixed"),b.css("width","")))},addNewClickHandler:function(a){a.preventDefault(),this.trigger("toggle:upload:attachment"),this.uploader&&this.uploader.refresh()},openEditAttachmentModal:function(a){wp.media({frame:"edit-attachments",controller:this,library:this.state().get("library"),model:a})},browseContent:function(a){var b=this.state();this.browserView=a.view=new wp.media.view.AttachmentsBrowser({controller:this,collection:b.get("library"),selection:b.get("selection"),model:b,sortable:b.get("sortable"),search:b.get("searchable"),filters:b.get("filterable"),date:b.get("date"),display:b.get("displaySettings"),dragInfo:b.get("dragInfo"),sidebar:"errors",suggestedWidth:b.get("suggestedWidth"),suggestedHeight:b.get("suggestedHeight"),AttachmentView:b.get("AttachmentView"),scrollElement:document}),this.browserView.on("ready",_.bind(this.bindDeferred,this)),this.errors=wp.Uploader.errors,this.errors.on("add remove reset",this.sidebarVisibility,this)},sidebarVisibility:function(){this.browserView.$(".media-sidebar").toggle(!!this.errors.length)},bindDeferred:function(){this.browserView.dfd&&this.browserView.dfd.done(_.bind(this.startHistory,this))},startHistory:function(){window.history&&window.history.pushState&&Backbone.history.start({root:window._wpMediaGridSettings.adminUrl,pushState:!0})}}),b.exports=d},{}]},{},[2]);