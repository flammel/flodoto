const availableColors = [
  "#FECACA",
  "#FDE68A",
  "#D9F99D",
  "#A5F3FC",
  "#C7D2FE",
  "#A7F3D0",
  "#60A5FA",
  "#F472B6",
  "#F5D0FE",
  "#FB923C",
];
const usedColors = {};
document.querySelectorAll(".colorize-ip").forEach(function (el) {
  const ip = el.textContent;
  if (
    !ip.match(/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/) &&
    !ip.match(/^[0-9a-fA-F:]+$/)
  ) {
    return;
  }
  if (!usedColors[ip]) {
    usedColors[ip] = availableColors.shift();
  }
  el.style.backgroundColor = usedColors[ip];
});
