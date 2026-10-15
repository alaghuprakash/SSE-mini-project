/**
 * CyberSec RBAC Portal — Main JavaScript
 * Sidebar toggle, confirmations, password strength, search debounce
 */

'use strict';

document.addEventListener('DOMContentLoaded', () => {

    // -------------------------------------------------------
    // Sidebar Toggle (mobile)
    // -------------------------------------------------------
    const sidebar      = document.getElementById('sidebar');
    const menuToggle   = document.getElementById('menuToggle');
    const sidebarToggle= document.getElementById('sidebarToggle');
    const overlay      = document.getElementById('sidebarOverlay');

    function openSidebar() {
        sidebar?.classList.add('open');
        overlay?.classList.add('show');
    }

    function closeSidebar() {
        sidebar?.classList.remove('open');
        overlay?.classList.remove('show');
    }

    menuToggle?.addEventListener('click', openSidebar);
    sidebarToggle?.addEventListener('click', closeSidebar);
    overlay?.addEventListener('click', closeSidebar);

    // -------------------------------------------------------
    // Auto-dismiss alerts after 5 seconds
    // -------------------------------------------------------
    document.querySelectorAll('.alert.fade.show').forEach(el => {
        setTimeout(() => {
            el.classList.remove('show');
            setTimeout(() => el.remove(), 300);
        }, 5000);
    });

    // -------------------------------------------------------
    // Password Strength Meter
    // -------------------------------------------------------
    const pwdInput   = document.getElementById('password');
    const strengthBar= document.querySelector('.password-strength-fill');
    const strengthLbl= document.getElementById('strengthLabel');

    if (pwdInput && strengthBar) {
        pwdInput.addEventListener('input', () => {
            const val = pwdInput.value;
            let score = 0;
            if (val.length >= 8)  score++;
            if (val.length >= 12) score++;
            if (/[A-Z]/.test(val))       score++;
            if (/[0-9]/.test(val))       score++;
            if (/[^A-Za-z0-9]/.test(val)) score++;

            const pct   = (score / 5) * 100;
            const colors = ['#f87171', '#fb923c', '#fbbf24', '#34d399', '#00f2fe'];
            const labels = ['Very Weak', 'Weak', 'Fair', 'Strong', 'Excellent'];

            strengthBar.style.width     = pct + '%';
            strengthBar.style.background= colors[score - 1] || '#1a2035';
            if (strengthLbl) strengthLbl.textContent = score > 0 ? labels[score - 1] : '';
        });
    }

    // -------------------------------------------------------
    // Confirm dialogs for dangerous actions
    // -------------------------------------------------------
    document.querySelectorAll('[data-confirm]').forEach(el => {
        el.addEventListener('click', e => {
            const msg = el.dataset.confirm || 'Are you sure?';
            if (!confirm(msg)) e.preventDefault();
        });
    });

    // -------------------------------------------------------
    // Search Debounce (form with data-autosearch)
    // -------------------------------------------------------
    const searchForms = document.querySelectorAll('[data-autosearch]');
    searchForms.forEach(form => {
        const input = form.querySelector('input[type="search"], input[name="q"], input[name="search"]');
        if (!input) return;
        let timer;
        input.addEventListener('input', () => {
            clearTimeout(timer);
            timer = setTimeout(() => form.submit(), 600);
        });
    });

    // -------------------------------------------------------
    // Tooltip initialization (Bootstrap 5)
    // -------------------------------------------------------
    document.querySelectorAll('[data-bs-toggle="tooltip"]').forEach(el => {
        new bootstrap.Tooltip(el, { trigger: 'hover' });
    });

    // -------------------------------------------------------
    // Dashboard Charts (if canvas elements present)
    // -------------------------------------------------------
    const roleChartEl = document.getElementById('roleDistributionChart');
    if (roleChartEl && typeof Chart !== 'undefined') {
        const data = JSON.parse(roleChartEl.dataset.values || '{}');
        new Chart(roleChartEl, {
            type: 'doughnut',
            data: {
                labels: ['Admin', 'Editor', 'Viewer'],
                datasets: [{
                    data: [data.admin || 0, data.editor || 0, data.viewer || 0],
                    backgroundColor: ['rgba(248,113,113,0.8)', 'rgba(251,146,60,0.8)', 'rgba(52,211,153,0.8)'],
                    borderColor:     ['#f87171', '#fb923c', '#34d399'],
                    borderWidth: 2,
                    hoverOffset: 4,
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: { color: '#94a3b8', padding: 16, font: { size: 12 } }
                    },
                    tooltip: {
                        callbacks: {
                            label: ctx => ` ${ctx.label}: ${ctx.parsed} user${ctx.parsed !== 1 ? 's' : ''}`
                        }
                    }
                },
                cutout: '65%',
            }
        });
    }

    const activityChartEl = document.getElementById('activityChart');
    if (activityChartEl && typeof Chart !== 'undefined') {
        const labels = JSON.parse(activityChartEl.dataset.labels || '[]');
        const values = JSON.parse(activityChartEl.dataset.values || '[]');
        new Chart(activityChartEl, {
            type: 'bar',
            data: {
                labels,
                datasets: [{
                    label: 'Events',
                    data: values,
                    backgroundColor: 'rgba(0,242,254,0.2)',
                    borderColor:    'rgba(0,242,254,0.8)',
                    borderWidth: 1,
                    borderRadius: 4,
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false },
                    tooltip: { mode: 'index' }
                },
                scales: {
                    x: {
                        ticks: { color: '#64748b', font: { size: 11 } },
                        grid:  { color: 'rgba(255,255,255,0.04)' }
                    },
                    y: {
                        ticks: { color: '#64748b', font: { size: 11 }, stepSize: 1 },
                        grid:  { color: 'rgba(255,255,255,0.04)' },
                        beginAtZero: true,
                    }
                }
            }
        });
    }

    // -------------------------------------------------------
    // Table row click (if data-href set)
    // -------------------------------------------------------
    document.querySelectorAll('tr[data-href]').forEach(row => {
        row.style.cursor = 'pointer';
        row.addEventListener('click', e => {
            if (!e.target.closest('a') && !e.target.closest('button') && !e.target.closest('form')) {
                window.location.href = row.dataset.href;
            }
        });
    });

    // -------------------------------------------------------
    // Theme Switcher & Persistence
    // -------------------------------------------------------
    const themeNames = {
        'cyber':   'Midnight Cyber',
        'emerald': 'Emerald SOC',
        'violet':  'Neon Synthwave',
        'light':   'Nordic Light'
    };

    function applyTheme(theme) {
        if (!themeNames[theme]) theme = 'cyber';
        document.documentElement.setAttribute('data-theme', theme);
        try {
            localStorage.setItem('rbac_theme', theme);
        } catch (e) {}

        // Update label in topbar
        const lbl = document.getElementById('currentThemeLabel');
        if (lbl) {
            lbl.textContent = themeNames[theme];
        }

        // Update checkmarks in dropdowns
        document.querySelectorAll('.theme-choice').forEach(btn => {
            const isMatch = btn.dataset.theme === theme;
            btn.classList.toggle('active', isMatch);
            const check = btn.querySelector('.theme-check');
            if (check) {
                check.classList.toggle('d-none', !isMatch);
            }
        });
    }

    // Initialize from storage or default
    const savedTheme = localStorage.getItem('rbac_theme') || 'cyber';
    applyTheme(savedTheme);

    // Event listener for theme choices
    document.querySelectorAll('.theme-choice').forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.preventDefault();
            const theme = btn.dataset.theme;
            applyTheme(theme);
        });
    });

    // -------------------------------------------------------
    // Global Interactive Cyber Particle Constellation Canvas
    // -------------------------------------------------------
    (function initCyberCanvas() {
        const canvas = document.getElementById('cyberCanvas');
        if (!canvas) return;
        const ctx = canvas.getContext('2d');

        let width = canvas.width = window.innerWidth;
        let height = canvas.height = window.innerHeight;

        window.addEventListener('resize', () => {
            width = canvas.width = window.innerWidth;
            height = canvas.height = window.innerHeight;
        });

        const mouse = { x: -1000, y: -1000, radius: 160 };
        window.addEventListener('mousemove', (e) => {
            mouse.x = e.clientX;
            mouse.y = e.clientY;
        });
        window.addEventListener('mouseout', () => {
            mouse.x = -1000;
            mouse.y = -1000;
        });

        function getThemeColors() {
            const t = document.documentElement.getAttribute('data-theme') || 'cyber';
            if (t === 'emerald') {
                return { node: 'rgba(16, 185, 129, 0.7)', line: '16, 185, 129' };
            }
            if (t === 'violet') {
                return { node: 'rgba(192, 132, 252, 0.7)', line: '192, 132, 252' };
            }
            if (t === 'light') {
                return { node: 'rgba(37, 99, 235, 0.45)', line: '37, 99, 235' };
            }
            // Cyber (default)
            return { node: 'rgba(0, 242, 254, 0.7)', line: '0, 242, 254' };
        }

        const count = Math.min(65, Math.floor((width * height) / 18000));
        const particles = [];

        for (let i = 0; i < count; i++) {
            particles.push({
                x: Math.random() * width,
                y: Math.random() * height,
                vx: (Math.random() - 0.5) * 0.7,
                vy: (Math.random() - 0.5) * 0.7,
                radius: Math.random() * 2 + 1,
                baseRadius: Math.random() * 2 + 1
            });
        }

        function animate() {
            ctx.clearRect(0, 0, width, height);
            const colors = getThemeColors();

            for (let i = 0; i < particles.length; i++) {
                const p = particles[i];
                p.x += p.vx;
                p.y += p.vy;

                if (p.x < 0 || p.x > width)  p.vx *= -1;
                if (p.y < 0 || p.y > height) p.vy *= -1;

                // Mouse interaction
                const dx = mouse.x - p.x;
                const dy = mouse.y - p.y;
                const dist = Math.sqrt(dx * dx + dy * dy);
                if (dist < mouse.radius) {
                    p.radius = p.baseRadius * 1.8;
                } else {
                    p.radius = p.baseRadius;
                }

                // Draw particle node
                ctx.beginPath();
                ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
                ctx.fillStyle = colors.node;
                ctx.fill();

                // Connect nearby nodes
                for (let j = i + 1; j < particles.length; j++) {
                    const p2 = particles[j];
                    const d = Math.sqrt((p.x - p2.x) ** 2 + (p.y - p2.y) ** 2);
                    if (d < 115) {
                        const alpha = (1 - d / 115) * 0.32;
                        ctx.beginPath();
                        ctx.moveTo(p.x, p.y);
                        ctx.lineTo(p2.x, p2.y);
                        ctx.strokeStyle = `rgba(${colors.line}, ${alpha})`;
                        ctx.lineWidth = 0.8;
                        ctx.stroke();
                    }
                }
            }

            requestAnimationFrame(animate);
        }
        animate();
    })();

});


