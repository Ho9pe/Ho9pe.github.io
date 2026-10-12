(function () {
  // Theme toggle: remembers an explicit choice, otherwise follows the OS.
  var root = document.documentElement;
  var btn = document.querySelector('.theme-toggle');
  function current() {
    var t = root.getAttribute('data-theme');
    if (t) return t;
    return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }
  if (btn) {
    btn.addEventListener('click', function () {
      var next = current() === 'dark' ? 'light' : 'dark';
      root.setAttribute('data-theme', next);
      try { localStorage.setItem('theme', next); } catch (e) {}
    });
  }

  // Copy buttons on code blocks.
  document.querySelectorAll('div.highlighter-rouge').forEach(function (block) {
    var pre = block.querySelector('pre');
    if (!pre || !navigator.clipboard) return;
    var b = document.createElement('button');
    b.className = 'copy-btn';
    b.type = 'button';
    b.textContent = 'Copy';
    b.addEventListener('click', function () {
      navigator.clipboard.writeText(pre.innerText).then(function () {
        b.textContent = 'Copied';
        setTimeout(function () { b.textContent = 'Copy'; }, 1400);
      });
    });
    block.appendChild(b);
  });

  // Blog tag filter (uses #tag in the URL so links from posts land filtered).
  var list = document.querySelector('.post-list');
  var filters = document.querySelectorAll('.filters button');
  if (list && filters.length) {
    function apply(tag) {
      filters.forEach(function (f) { f.setAttribute('aria-pressed', String(f.dataset.tag === tag)); });
      list.querySelectorAll('li').forEach(function (li) {
        var tags = (li.dataset.tags || '').split(' ');
        li.hidden = !(tag === 'all' || tags.indexOf(tag) !== -1);
      });
    }
    filters.forEach(function (f) {
      f.addEventListener('click', function () {
        var tag = f.dataset.tag;
        apply(tag);
        history.replaceState(null, '', tag === 'all' ? location.pathname : '#' + tag);
      });
    });
    var initial = decodeURIComponent(location.hash.replace('#', ''));
    var known = Array.prototype.some.call(filters, function (f) { return f.dataset.tag === initial; });
    apply(known ? initial : 'all');
  }
})();
