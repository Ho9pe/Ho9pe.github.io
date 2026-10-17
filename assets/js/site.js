(function () {
  var root = document.documentElement;
  var each = function (list, fn) { Array.prototype.forEach.call(list, fn); };

  // Theme toggle: remembers an explicit choice, otherwise follows the OS.
  var btn = document.querySelector('.theme-toggle');
  function currentTheme() {
    var t = root.getAttribute('data-theme');
    if (t) return t;
    return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }
  if (btn) {
    btn.addEventListener('click', function () {
      var next = currentTheme() === 'dark' ? 'light' : 'dark';
      root.setAttribute('data-theme', next);
      try { localStorage.setItem('theme', next); } catch (e) {}
    });
  }

  // Code blocks: a header bar with the language and a copy button.
  var copyIcon = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V6a2 2 0 0 1 2-2h9"/></svg>';
  each(document.querySelectorAll('div.highlighter-rouge'), function (block) {
    var pre = block.querySelector('pre');
    if (!pre) return;
    var m = block.className.match(/language-([\w+#.-]+)/);
    var lang = m ? m[1] : 'text';
    if (lang === 'plaintext') lang = 'text';
    var head = document.createElement('div');
    head.className = 'code-head';
    var label = document.createElement('span');
    label.textContent = lang;
    head.appendChild(label);
    if (navigator.clipboard) {
      var b = document.createElement('button');
      b.className = 'copy-btn';
      b.type = 'button';
      b.innerHTML = copyIcon + '<span>Copy</span>';
      b.addEventListener('click', function () {
        navigator.clipboard.writeText(pre.innerText).then(function () {
          b.lastChild.textContent = 'Copied';
          setTimeout(function () { b.lastChild.textContent = 'Copy'; }, 1400);
        });
      });
      head.appendChild(b);
    }
    block.insertBefore(head, block.firstChild);
  });

  // Tables in posts: a scrolling wrapper, so the table can fill the column.
  each(document.querySelectorAll('.prose table'), function (table) {
    var wrap = document.createElement('div');
    wrap.className = 'table-wrap';
    table.parentNode.insertBefore(wrap, table);
    wrap.appendChild(table);
  });

  // Posts: "On this page" rail built from the h2s, scroll spy, reading progress.
  var article = document.querySelector('article.post');
  if (article) {
    var prose = article.querySelector('.prose');
    var rail = article.querySelector('.toc-rail');
    var bar = document.querySelector('.read-progress span');
    // Sections are the h2s, or the h3s in a post with fewer than two h2s. Every
    // section gets a running number (01, 02 ...) in the rail and on its heading,
    // replacing any numbering typed in the heading ("3.", "4.1", "Step 2:",
    // "Phase 5 -"); an appendix gets a dot. "Stage N" stays: it names a stage.
    var pick = function (sel) { return prose ? Array.prototype.slice.call(prose.querySelectorAll(sel)) : []; };
    var heads = pick('h2[id]');
    if (heads.length < 2) heads = pick('h3[id]');
    var typedNumber = /^\s*(?:(?:step|phase)\s+\d+\s*(?:[:.)]|-)\s*|\d+(?:\.\d+)*[.)]\s+|\d+\.\d+(?:\.\d+)*\s+)/i;
    var links = [];
    if (rail && heads.length >= 2) {
      var ol = rail.querySelector('ol');
      var count = 0;
      heads.forEach(function (h) {
        var first = h.firstChild;
        if (first && first.nodeType === 3) first.nodeValue = first.nodeValue.replace(typedNumber, '');
        var text = h.textContent.trim();
        var appendix = /^appendix\b/i.test(text);
        var label = appendix ? '·' : (++count < 10 ? '0' : '') + count;
        if (!appendix) {
          var badge = document.createElement('span');
          badge.className = 'h-num';
          badge.setAttribute('aria-hidden', 'true');
          badge.textContent = label;
          h.insertBefore(badge, h.firstChild);
        }
        var li = document.createElement('li');
        var a = document.createElement('a');
        a.href = '#' + h.id;
        var n = document.createElement('span');
        n.className = 'n';
        n.textContent = label;
        a.appendChild(n);
        a.appendChild(document.createTextNode(text));
        li.appendChild(a);
        ol.appendChild(li);
        links.push(a);
      });
      rail.hidden = false;
      document.body.classList.add('has-rail-toc');
      // Open beside the post on wide screens; a collapsed list above it on narrow ones.
      var wide = window.matchMedia('(min-width: 1080px)');
      var fit = function () { rail.open = wide.matches; };
      fit();
      if (wide.addEventListener) wide.addEventListener('change', fit);
    }
    var ticking = false;
    var update = function () {
      ticking = false;
      if (bar) {
        var top = article.getBoundingClientRect().top + window.scrollY;
        var span = article.offsetHeight - window.innerHeight;
        var p = span > 0 ? (window.scrollY - top) / span : 1;
        bar.style.width = Math.max(0, Math.min(1, p)) * 100 + '%';
      }
      if (links.length) {
        var current = -1;
        heads.forEach(function (h, i) { if (h.getBoundingClientRect().top < 140) current = i; });
        links.forEach(function (a, i) {
          if (i === current) a.setAttribute('aria-current', 'true');
          else a.removeAttribute('aria-current');
        });
      }
    };
    window.addEventListener('scroll', function () {
      if (!ticking) { ticking = true; window.requestAnimationFrame(update); }
    }, { passive: true });
    window.addEventListener('resize', update);
    update();
  }

  // Blog index: series, topic and text filters. The active series/topic live in
  // the URL hash (#deep-dives, #pwn, #alpacahack-daily+pwn) so links land filtered.
  var blog = document.querySelector('[data-blog]');
  if (blog) {
    var rows = Array.prototype.slice.call(blog.querySelectorAll('.post-row'));
    var groupBtns = Array.prototype.slice.call(blog.querySelectorAll('[data-group-filter]'));
    var topicBtns = Array.prototype.slice.call(blog.querySelectorAll('[data-topic-filter]'));
    var years = blog.querySelectorAll('.year-group');
    var search = blog.querySelector('#post-search');
    var results = blog.querySelector('[data-results]');
    var barClear = blog.querySelector('.results-bar [data-clear]');
    var empty = blog.querySelector('[data-empty]');
    var state = { group: 'all', topic: '', q: '' };

    var render = function (writeHash) {
      var q = state.q.trim().toLowerCase();
      var shown = 0;
      rows.forEach(function (r) {
        var ok = (state.group === 'all' || r.dataset.group === state.group) &&
          (!state.topic || (' ' + r.dataset.tags + ' ').indexOf(' ' + state.topic + ' ') !== -1) &&
          (!q || r.dataset.search.indexOf(q) !== -1);
        r.hidden = !ok;
        if (ok) shown++;
      });
      each(years, function (y) {
        var n = y.querySelectorAll('.post-row:not([hidden])').length;
        y.hidden = n === 0;
        y.querySelector('[data-year-count]').textContent = n + (n === 1 ? ' post' : ' posts');
      });
      groupBtns.forEach(function (b) { b.setAttribute('aria-pressed', String(b.dataset.groupFilter === state.group)); });
      topicBtns.forEach(function (b) { b.setAttribute('aria-pressed', String(b.dataset.topicFilter === state.topic)); });
      var filtered = state.group !== 'all' || !!state.topic || !!q;
      results.textContent = filtered ? 'Showing ' + shown + ' of ' + rows.length + ' posts' : rows.length + ' posts, newest first';
      barClear.hidden = !filtered;
      empty.hidden = shown !== 0;
      if (writeHash) {
        var parts = [];
        if (state.group !== 'all') parts.push(state.group);
        if (state.topic) parts.push(state.topic);
        history.replaceState(null, '', parts.length ? '#' + parts.join('+') : location.pathname + location.search);
      }
    };

    var fromHash = function () {
      state.group = 'all';
      state.topic = '';
      decodeURIComponent(location.hash.replace('#', '')).split('+').forEach(function (part) {
        if (!part) return;
        var g = groupBtns.filter(function (b) {
          return b.dataset.groupFilter === part || (' ' + (b.dataset.aliases || '') + ' ').indexOf(' ' + part + ' ') !== -1;
        })[0];
        if (g) { state.group = g.dataset.groupFilter; return; }
        if (topicBtns.some(function (b) { return b.dataset.topicFilter === part; }) ||
            rows.some(function (r) { return (' ' + r.dataset.tags + ' ').indexOf(' ' + part + ' ') !== -1; })) {
          state.topic = part;
        }
      });
    };

    groupBtns.forEach(function (b) {
      b.addEventListener('click', function () { state.group = b.dataset.groupFilter; render(true); });
    });
    topicBtns.forEach(function (b) {
      b.addEventListener('click', function () {
        state.topic = state.topic === b.dataset.topicFilter ? '' : b.dataset.topicFilter;
        render(true);
      });
    });
    if (search) search.addEventListener('input', function () { state.q = search.value; render(false); });
    each(blog.querySelectorAll('[data-clear]'), function (c) {
      c.addEventListener('click', function () {
        state.group = 'all';
        state.topic = '';
        state.q = '';
        if (search) search.value = '';
        render(true);
      });
    });
    window.addEventListener('hashchange', function () { fromHash(); render(false); });
    fromHash();
    render(false);
  }
})();
