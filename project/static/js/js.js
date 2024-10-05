// ### COLUMN TOGGLING ###
// Toggle hidden data columns when checkboxes checked/unchecked (event listener)
$(document).ready(function() {
    $('input[type="checkbox"]').click(function() {
        var inputValue = $(this).attr("value");
        $("." + inputValue).toggle();
    });
});

// Hide most data columns, only show the most important - to make it somewhat readable on mobiles.
// To-do: Should save which columns are currently checked in a cookie so user's current set can persist across pages.

function apply_simple_view() {

    // Columns to hide:
    const inactiveData = document.querySelectorAll("th.sv0, td.sv0"); // .sv0 = inactive for simple view
    const inactiveCheckboxes = document.querySelectorAll("div#dataToggles input.sv0");
    // Columns to display:
    const activeData = document.querySelectorAll("th.sv1, td.sv1"); // .sv1 = active for simple view
    const activeCheckboxes = document.querySelectorAll("div#dataToggles input.sv1");

    // Hide inactiveData columns
    for (let i = 0; i < inactiveData.length; i++) {
        inactiveData[i].style.display = "none";
        inactiveData[i].classList.add("hidden");
    };
    // Uncheck inactiveData checkboxes
    for (let i = 0; i < inactiveCheckboxes.length; i++) {
        inactiveCheckboxes[i].checked = false;
    };

    // Display activeData columns
    for (let i = 0; i < activeData.length; i++) {
        activeData[i].style.display = "flexbox";
        activeData[i].classList.remove("hidden");
        //activeData[i].style.width = "10vw";
    };
    // Check activeData checkboxes
    for (let i = 0; i < activeCheckboxes.length; i++) {
        activeCheckboxes[i].checked = true;
    };

    // refactoring - Check activeData checkboxes
    /*
    activeCheckboxes.forEach((el, i) => {
        el[i].checked = true;
    });
    */
}

// Media query for mobile devices; if mobile, call apply_simple_view()
const mediaQuery = window.matchMedia('only screen and (orientation: portrait) and ((pointer: coarse) or (pointer: none))')
function handleTabletChange(e) {
    if (e.matches) {
      console.log('Client appears to be a mobile device; applying simple data view.')
      apply_simple_view()
    }
}
//mediaQuery.addListener(handleTabletChange) //addListener deprecated
mediaQuery.addEventListener('change', handleTabletChange)
handleTabletChange(mediaQuery)

// ### COLOR THEMES ###

// Fetch user's preferred color theme (via /profile/get_theme), and add theme class to <body> element.
// Otherwise, if it's a cached route, the theme (class) won't take effect until cache expires.
function apply_pref_theme() {
    fetch('/profile/get_theme')
        .then(x => x.text())
        .then(y => document.body.classList = y);
}
apply_pref_theme();

// Event listener; Submit theme form on option change, + display loading note.
document.getElementById("pref_theme").addEventListener("change", function() {
	document.getElementById("footer_loading_note").style.display="block";
    // Submit form.
    const formElement = document.getElementById('theme_form');
    formElement.submit();
});


// ### MODALS ###

// Show modal dialog when a row's delete-button is clicked. (jquery version) (reference: https://forum.jquery.com/portal/en/community/topic/how-to-pass-a-dynamic-div-id-to-a-function-in-jquery)
// Usage: .delete-button element should have attr for_id="row['id']". Then use $(this).attr("for_id") to construct Id, then getElementById
/*
$('.delete-button').click(function(e) {
    var modal_id = $(this).attr("for_id");
    document.getElementById("delete_confirmation_modal_".concat(modal_id)).style.display='block';
});
*/

// Refactoring without jQuery: Show modal when a row's delete-button is clicked (event listener).
// Get all elements with class "delete-button"
var deleteButtons = document.querySelectorAll('.delete-button');
// Add click event listener to each delete button
deleteButtons.forEach(function(button) {
    button.addEventListener('click', function(e) {
        // Get the value of "for_id" attribute
        var modalId = this.getAttribute('for_id');

        // Construct id of the modal div
        var modalElementId = "delete_confirmation_modal_".concat(modalId);

        // Display the modal element
        var modalElement = document.getElementById(modalElementId);
        if (modalElement) {
            modalElement.style.display = 'block';
        }
    });
});

// Close modal when click cancel button OR x button (any with class=modal_close)
$('.modal_close').click(function(e) {
    var modal_id = $(this).attr("for_id");
    document.getElementById("delete_confirmation_modal_".concat(modal_id)).style.display='none';
});

// Close modal when you click anywhere outside of it.
var modals = document.querySelectorAll('.modal');
$('.modal').click(function(e) {
    modals.forEach(function(modal) {
        if (e.target == modal && modal.contains(e.target)) {
            console.log("Clicked outside modal; closing.");
            modal.style.display = "none";
        }
    });
});

// ### END MODALS ###

// ### Get 7 days + 1 day top IPs from /analysis/aj/tops
// Make 3 separate requests; past 1 day, past 7 days, and past 30 days,
// and update the info in the aside element.

async function getAllTops_b() {
    try {
        if (document.querySelector('div#tops')) {
            // Fetch endpoint (1 day)
            const responseD = await fetch('/analysis/api/tops/1');
            const dataD = await responseD.json();
            const topIpDay = dataD;
            // Update DOM (day)
            document.querySelector("a#top_daily").innerHTML = topIpDay.remoteaddr;
            document.querySelector("a#top_daily").setAttribute("href", "/stats/ip/" + topIpDay.remoteaddr);
            document.querySelector("a#graph_daily").setAttribute("href", "/stats/ip/per_day?ip=" + topIpDay.remoteaddr + "&days=7");
            document.querySelector("span#top_daily_count").innerHTML = topIpDay.count;
            // Fetch endpoint (7 days)
            const responseW = await fetch('/analysis/api/tops/7');
            const dataW = await responseW.json();
            const topIpWeek = dataW;
            // Update DOM (week)
            document.querySelector("a#top_weekly").innerHTML = topIpWeek.remoteaddr;
            document.querySelector("a#top_weekly").setAttribute("href", "/stats/ip/" + topIpWeek.remoteaddr);
            document.querySelector("a#graph_weekly").setAttribute("href", "/stats/ip/per_day?ip=" + topIpWeek.remoteaddr + "&days=7");
            document.querySelector("span#top_weekly_count").innerHTML = topIpWeek.count;
            // Fetch endpoint (30 days)
            const responseM = await fetch('/analysis/api/tops/30');
            const dataM = await responseM.json();
            const topIpMonth = dataM;
            // Update DOM (month)
            document.querySelector("a#top_monthly").innerHTML = topIpMonth.remoteaddr;
            document.querySelector("a#top_monthly").setAttribute("href", "/stats/ip/" + topIpMonth.remoteaddr);
            document.querySelector("a#graph_monthly").setAttribute("href", "/stats/ip/per_day?ip=" + topIpMonth.remoteaddr + "&days=31");
            document.querySelector("span#top_monthly_count").innerHTML = topIpMonth.count;
        } else {
            console.log("Didn't find a div#tops - not fetching tops.");
        }
    }
    catch (error) {
        console.error('Error fetching data: ', error);
    }
}
getAllTops_b();

/*
// ### "Scroll-to-top" button
let toTopBtn = document.getElementById("toTop");
// When the user scrolls down 20px from the top of the document, show the button
window.onscroll = function() {scrollFunction()};
function scrollFunction() {
  if (document.body.scrollTop > 500 || document.documentElement.scrollTop > 500) {
    toTopBtn.style.display = "block";
  } else {
    toTopBtn.style.display = "none";
  }
}
*/
// When the user clicks on the button, scroll to the top of the document
function topFunction() {
  document.body.scrollTop = 0; // For Safari
  document.documentElement.scrollTop = 0; // For Chrome, Firefox, IE and Opera
} 
// Event listener for the "Back to top" button
$(document).ready(function() {
    $('#toTop').click(function() {
        topFunction();
    });
});
