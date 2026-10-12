---
layout: page
title: Research
permalink: /research/
lede: Machine learning for systems security, with a focus on whether learned detectors survive real-world change.
---

<div class="cards">
  <article class="card feature">
    <p class="post-kicker" style="margin:0;">Undergraduate thesis · journal paper under review</p>
    <h3>Temporal Generalization and Explanation Stability of Control Flow Graph Neural Networks for Malware Detection</h3>
    <p><span class="me">Md. Asif Sajeed</span>, Md. Nazrul Islam Mondal, Md Ashraful Hossen Akash · under review at the <em>Journal of Information Security and Applications</em></p>
    <p>Malware detectors are usually tested on a random split of samples from one period, which says little about how they behave on the next year's binaries. I built a fully static pipeline that lifts Windows PE files into control flow graphs with angr and encodes every basic block. I then trained twelve graph neural network variants and a flat, topology-free baseline on samples from 2024–2025 and scored them once on a disjoint 2026 corpus.</p>
    <ul style="margin:4px 0 6px;padding-left:20px;color:var(--muted);font-size:15px;">
      <li><strong>Rank reversal.</strong> The flat baseline was among the best in-distribution models (AUC 0.932) but among the worst after the time boundary (0.807), while PNA held 0.879.</li>
      <li><strong>The message-passing operator matters.</strong> Operator choice significantly changed robustness (Friedman p = 0.0006). Recalibration did not fix the gap, and ensembling fragile operators did not replace choosing a robust one.</li>
      <li><strong>Explanations are architecture-specific.</strong> GNNExplainer attributions did not drift over time, but two architectures agreed on important blocks only at chance level.</li>
      <li><strong>A design derived from the findings.</strong> CFGNet-v2 matched the best searched operator without any search.</li>
    </ul>
    <p class="plinks"><a href="https://arxiv.org/abs/2609.24280">arXiv:2609.24280</a> · <a href="https://github.com/Ho9pe/TG-CFG">Code (TG-CFG)</a></p>
  </article>
</div>

## Publications

<ol class="pubs">
  <li>
    <span class="status">Under review</span>
    <span class="me">Md. Asif Sajeed</span>, M. N. I. Mondal, and M. A. H. Akash.
    "Temporal Generalization and Explanation Stability of Control Flow Graph Neural Networks for Malware Detection."
    <span class="venue">Journal of Information Security and Applications</span>, 2026.
    <div class="plinks"><a href="https://arxiv.org/abs/2609.24280">Preprint</a><a href="https://github.com/Ho9pe/TG-CFG">Code</a></div>
  </li>
  <li>
    <span class="me">Md. Asif Sajeed</span>, S. Afroge, M. A. H. Akash, A. Khayer, and A. Al Mamun.
    "Memory-Efficient Deep Learning Architectures for Water Body Segmentation in Satellite Imagery: A Comparative Analysis and Ensemble Approach."
    <span class="venue">28th International Conference on Computer and Information Technology (ICCIT)</span>, IEEE, Cox's Bazar, Dec 2025.
    <div style="color:var(--muted);font-size:15px;margin:4px 0;">A comparison of seven segmentation architectures on Sentinel-2 imagery, trading accuracy against parameter count, plus a Dice-weighted ensemble and a compact U-Net that cuts parameters substantially while staying competitive.</div>
    <div class="plinks"><a href="https://doi.org/10.1109/ICCIT68739.2025.11491634">DOI</a><a href="https://github.com/Ho9pe/WaterbodySegmentation">Code</a></div>
  </li>
  <li>
    A. Khayer, S. Afroge, A. Al Mamun, <span class="me">Md. Asif Sajeed</span>, and M. A. H. Akash.
    "Transformer-Based Multi-Label Disease Prediction from Radiology Reports."
    <span class="venue">28th International Conference on Computer and Information Technology (ICCIT)</span>, IEEE, Cox's Bazar, Dec 2025.
    <div class="plinks"><a href="https://doi.org/10.1109/ICCIT68739.2025.11491786">DOI</a></div>
  </li>
  <li>
    M. A. H. Akash, S. Afroge, <span class="me">Md. Asif Sajeed</span>, M. Barkullah, and A. Khayer.
    "An Explainable Deep Learning Framework for Multi-Class Alzheimer's Diagnosis With Multi-Scale CNN."
    <span class="venue">IEEE 2nd International Conference on Quantum Photonics, Artificial Intelligence &amp; Networking (QPAIN)</span>, Chittagong, 2026.
    <div style="color:var(--muted);font-size:15px;margin:4px 0;">A multi-scale CNN for four-stage Alzheimer's classification from structural MRI, ensembled with Xception and ResNet50. Predictions are explained with Grad-CAM, Integrated Gradients and LIME, and the model is deployed as a lightweight Streamlit app.</div>
    <div class="plinks"><a href="https://doi.org/10.1109/QPAIN69676.2026.11545771">DOI</a></div>
  </li>
</ol>

Full list on [Google Scholar]({{ site.social.scholar }}).

## Research experience

<ul class="timeline">
  <li><div class="t-head"><strong>Undergraduate thesis: graph neural networks for malware detection</strong><span class="when">2025 – 2026</span></div>
    <div class="sub">RUET · Supervisor: Prof. Dr. Md. Nazrul Islam Mondal · External examiner: Md. Azmain Yakin Srizon · Python, PyTorch Geometric, angr</div></li>
  <li><div class="t-head"><strong>Undergraduate research group lead</strong><span class="when">2024 – 2026</span></div>
    <div class="sub">RUET · Supervisor: Shyla Afroge · Led four CNN and NLP projects across remote sensing, clinical text and medical imaging, three of which were published in IEEE proceedings. I coordinated experimental design, division of work and manuscript preparation.</div></li>
</ul>

## Skills

- **Machine learning:** graph neural networks, deep learning, explainable AI, NLP, computer vision · PyTorch, PyTorch Geometric, scikit-learn, LightGBM, NumPy, pandas
- **Security:** malware analysis, reverse engineering, static and dynamic binary analysis, digital forensics, web exploitation · IDA, Ghidra, angr, x64dbg, Volatility 3, Wireshark, pwntools
- **Programming:** Python, C, C++, x86/x64 assembly, JavaScript/TypeScript, PHP, SQL
