$(function() {

    $(".input input").focus(function() {
 
       $(this).parent(".input").each(function() {
          $("label", this).css({
             "line-height": "18px",
             "font-size": "18px",
             "font-weight": "100",
             "top": "0px"
          })