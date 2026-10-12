export function render(el, html) {
  el.innerHTML = html;
  const data = JSON.parse(JSON.stringify(window.state));
  localStorage.setItem('authToken', data.token);
  console.log(eval('1+1'));
}
