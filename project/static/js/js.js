document.getElementById("themeToggleButton").addEventListener("click", function() {
	var element = document.body;
    element.classList.toggle("theme-blue");
});

$(document).ready(function() {
    $('input[type="checkbox"]').click(function() {
        var inputValue = $(this).attr("value");
        $("." + inputValue).toggle();
    });
});
