export default function initMatrixBG() {
  const canvas = document.getElementById('matrix-bg');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');

  let width = (canvas.width = window.innerWidth);
  let height = (canvas.height = window.innerHeight);
  const columnWidth = 16; // spacing between streams
  const columns = Math.floor(width / columnWidth);
  const drops = Array.from({ length: columns }, () => Math.random() * height);

  const chars = '01';
  const fontSize = 14;
  ctx.font = `${fontSize}px Inter, monospace`;

      const draw = () => {
      // Transparent overlay for trail effect
      ctx.fillStyle = 'rgba(255, 255, 255, 0.08)';
      ctx.fillRect(0, 0, width, height);
  
      ctx.fillStyle = 'rgba(100,116,139,0.15)';
      ctx.shadowColor = 'rgba(0,0,0,0.05)';
      ctx.shadowBlur = 6;

    for (let i = 0; i < drops.length; i++) {
      const text = chars[Math.floor(Math.random() * chars.length)];
      const x = i * columnWidth;
      const y = drops[i] * fontSize;
      ctx.fillText(text, x, y);

      if (y > height && Math.random() > 0.975) {
        drops[i] = 0;
      }
      drops[i] += 0.5; // slow, subtle
    }
  };

  const onResize = () => {
    width = canvas.width = window.innerWidth;
    height = canvas.height = window.innerHeight;
  };

  window.addEventListener('resize', onResize);
  onResize();

  // Run at low FPS for subtle background
  setInterval(draw, 100);
}


