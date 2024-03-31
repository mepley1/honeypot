/* Toggle between adding and removing the "responsive" class to topnav when the user clicks on the icon */
function toggle_res_class() {
    var x = document.getElementById("myTopnav");
    if (x.className === "topnav") {
      x.className += " responsive";
    } else {
      x.className = "topnav";
    }
  } 

// Toggle nav menu responsive class on icon click (event listener for above)
$("#nav_toggle_btn").click(function() {
    toggle_res_class();
});

// Event listeners for dropdown menus
$(document).ready(function() {
  $('.drop_btn_1').click(function() {
    var menuItems = $('span.drop_hidden_1');
    $(menuItems).toggle();
  });
});

$(document).ready(function() {
  $('.drop_btn_2').click(function() {
    var menuItems = $('span.drop_hidden_2');
    $(menuItems).toggle();
  });
});

$(document).ready(function() {
  $('.drop_btn_3').click(function() {
    var menuItems = $('span.drop_hidden_3');
    $(menuItems).toggle();
  });
});

