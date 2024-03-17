// Toggle hidden data columns
$(document).ready(function() {
    $('input[type="checkbox"]').click(function() {
        var inputValue = $(this).attr("value");
        $("." + inputValue).toggle();
    });
});

// Fetch user's preferred color theme, and add theme class to <body> element.
// Otherwise the theme (class) won't be applied until cache expires.
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
