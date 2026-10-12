---
layout: page
title: Projects
permalink: /projects/
lede: Research code, systems coursework and things I've built along the way.
---

## Research code

<div class="cards">
  <article class="card">
    <h3><a href="https://github.com/Ho9pe/TG-CFG">TG-CFG</a></h3>
    <p>The code behind my thesis paper. A staged pipeline that extracts control flow graphs from Windows PE binaries with angr, trains GNN variants and a flat baseline, and runs the temporal evaluation, statistics and explanation-stability analysis. Configs, tests and reproduction notes are included.</p>
    <div class="meta">Python · PyTorch Geometric · angr</div>
  </article>
  <article class="card">
    <h3><a href="https://github.com/Ho9pe/WaterbodySegmentation">Water body segmentation</a></h3>
    <p>Reference implementation for our ICCIT 2025 paper: seven deep segmentation architectures and a Dice-weighted ensemble on Sentinel-2 imagery with NDWI-derived masks, refactored from the original notebook into a package with command-line stages.</p>
    <div class="meta">Python · TensorFlow/Keras</div>
  </article>
  <article class="card">
    <h3><a href="https://github.com/Ho9pe/PDP-ParallelAudit">PDP-ParallelAudit</a></h3>
    <p>A password-hash auditing tool for a parallel computing course. It has dictionary and brute-force attacks in serial and OpenMP versions, and MD5 and SHA-1 written from RFC 1321 and RFC 3174 with no crypto libraries, to measure speed-up and throughput.</p>
    <div class="meta">C · OpenMP</div>
  </article>
</div>

## Software

<div class="cards">
  <article class="card">
    <h3><a href="https://github.com/Ho9pe/NIBEDITO">Nibedito</a></h3>
    <p>A full-stack gift and e-commerce store with a catalogue, cart, checkout, orders, reviews, coupons and an admin panel. JWT authentication in httpOnly cookies, bcrypt, email and phone verification, and an API hardened with rate limiting and server-side validation.</p>
    <div class="meta">Next.js · React · TypeScript · Express · MongoDB</div>
  </article>
  <article class="card">
    <h3><a href="https://github.com/Ho9pe/Routine_Management">University routine manager</a></h3>
    <p>A class-routine web app with separate roles for students, teachers and administrators. It covers course management, schedule preferences and automated routine generation.</p>
    <div class="meta">JavaScript · Node.js</div>
  </article>
  <article class="card">
    <h3><a href="https://github.com/Ho9pe/CollabTask-laravel">CollabTask</a></h3>
    <p>A collaborative task manager with shared boards, built with Laravel and Tailwind CSS.</p>
    <div class="meta">PHP · Laravel · Tailwind CSS</div>
  </article>
  <article class="card">
    <h3><a href="https://github.com/Ho9pe/File_Manager">File Manager</a></h3>
    <p>An ad-free, minimalistic Android file manager.</p>
    <div class="meta">Java · Android</div>
  </article>
  <article class="card">
    <h3><a href="https://github.com/Ho9pe/yt-sum">yt-sum</a></h3>
    <p>A Streamlit app that fetches YouTube transcripts and turns them into structured notes with the Gemini API.</p>
    <div class="meta">Python · Streamlit · Gemini API</div>
  </article>
  <article class="card">
    <h3><a href="https://github.com/Ho9pe/Discord-Gemini-Bot">Discord Gemini bot</a></h3>
    <p>A Discord bot that answers in chat using Google's Gemini models.</p>
    <div class="meta">JavaScript · discord.js</div>
  </article>
  <article class="card">
    <h3><a href="https://github.com/Ho9pe/Population-Prediction-Model">Population prediction model</a></h3>
    <p>Forecasts a city's population by combining Newton's interpolation, the Newton–Raphson method and curve fitting on historical data.</p>
    <div class="meta">Python · NumPy · pandas</div>
  </article>
</div>

## Analysis &amp; design work

- **Dynamic Feedback Management System, Dynamic Solution Innovators (Mar 2025).** Designed a multi-role feedback platform with OTP-verified submission, automated approver assignment and a multi-stage approval workflow. I delivered requirements, use-case, component and ER diagrams, a normalised schema, Figma prototypes, a REST API structure and a five-sprint plan.
- **Information systems analysis of Robi Axiata PLC (2025).** In a four-person team, analysed a national telecom operator's systems. The work covered a feasibility study, stakeholder questionnaires, data-flow models, a weighted evaluation of candidate systems, and a cost-benefit analysis with break-even and ROI projections, in a 95-page report.
