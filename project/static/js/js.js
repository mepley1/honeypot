// Toggle hidden data columns when checkboxes checked/unchecked (event listener)
$(document).ready(function() {
    $('input[type="checkbox"]').click(function() {
        var inputValue = $(this).attr("value");
        $("." + inputValue).toggle();
    });
});

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

// Testing: show/hide sets of data for a more compact view. Will use later for a mobile view. (function checks a pre-made set of checkboxes)
// document.querySelector("#simple_view_btn").addEventListener("click", function() {
function apply_simple_view() {
    const inactiveData = document.querySelectorAll(".dataID, .dataScheme, .dataHost, .dataURL, .dataContentType, .dataHostname, .dataTime, .dataUA, .dataHeaders, .dataReferer, .dataCountry");
    const activeData = document.querySelectorAll(".dataIP, .dataMethod, .dataPath, .dataQueryString, .dataPostData, .dataLinks, .dataReported");
    // Uncheck inactiveData columns
    for (let i = 0; i < inactiveData.length; i++) {
        inactiveData[i].style.display = "none";
        inactiveData[i].classList.add("hidden");
    };
    // Check activeData columns
    for (let i = 0; i < activeData.length; i++) {
        activeData[i].style.display = "flexbox";
        activeData[i].classList.remove("hidden");
        activeData[i].style.width = "10vw";
    };
}
// );

// testing with jquery https://forum.jquery.com/portal/en/community/topic/how-to-pass-a-dynamic-div-id-to-a-function-in-jquery
// Show modal dialog when a row's delete-button is clicked.
// WORKING: use for_id="row['id']" in HTML element attr, then use $(this).attr("for_id") to getElementById

/*$('.delete-button').click(function(e) {
    var modal_id = $(this).attr("for_id");
    document.getElementById("delete_confirmation_modal_".concat(modal_id)).style.display='block';
});*/

// Refactoring without jQuery: Show modal when a row's delete-button is clicked (event listener).
// Get all elements with the class name "delete-button"
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

// close modal (click close button OR x button with class=modal_close)
$('.modal_close').click(function(e) {
    var modal_id = $(this).attr("for_id");
    document.getElementById("delete_confirmation_modal_".concat(modal_id)).style.display='none';
});

// Close modal when you click anywhere outside of it. (refactored without deprecated window.event)
var modals = document.querySelectorAll('.modal');
$('.modal').click(function(e) {
    modals.forEach(function(modal) {
        if (e.target == modal && modal.contains(e.target)) {
            modal.style.display = "none";
        }
    });
});
