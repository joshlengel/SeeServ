function onPressLeft() {
    let left = document.getElementById("left-button");
    let right = document.getElementById("right-button");

    left.classList.remove("visible-button");
    right.classList.add("visible-button");
    left.classList.add("invisible-button");
    right.classList.remove("invisible-button");
}

function onPressRight() {
    let left = document.getElementById("left-button");
    let right = document.getElementById("right-button");

    left.classList.add("visible-button");
    right.classList.remove("visible-button");
    left.classList.remove("invisible-button");
    right.classList.add("invisible-button");
}