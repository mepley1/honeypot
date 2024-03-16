// Toggle hidden data columns
$(document).ready(function() {
    $('input[type="checkbox"]').click(function() {
        var inputValue = $(this).attr("value");
        $("." + inputValue).toggle();
    });
});

// Fetch user's preferred color theme, and add theme class to <body> element.
// Otherwise the theme (class) won't be applied until cache expires.
fetch('/profile/get_theme')
    .then(x => x.text())
    .then(y => document.body.classList = y);
