jQuery(function(a){return"undefined"!=typeof woocommerce_params&&(a("#add_payment_method").on("click init_add_payment_method",".payment_methods input.input-radio",function(){if(a(".payment_methods input.input-radio").length>1){var b=a("div.payment_box."+a(this).attr("ID"));a(this).is(":checked")&&!b.is(":visible")&&(a("div.payment_box").filter(":visible").slideUp(250),a(this).is(":checked")&&a("div.payment_box."+a(this).attr("ID")).slideDown(250))}else a("div.payment_box").show()}).find("input[name=payment_method]:checked").click(),a("#add_payment_method").submit(function(){a("#add_payment_method").block({message:null,overlayCSS:{background:"#fff",opacity:.6}})}),void a(document.body).trigger("init_add_payment_method"))});