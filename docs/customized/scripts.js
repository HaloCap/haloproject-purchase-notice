/* Toast */
const showToast = () => {
    const t = document.getElementById('toast');
    t.classList.add('show');
    setTimeout(() => t.classList.remove('show'), 2000);
  };
  
/* 複製到剪貼簿：支援行動裝置 fallback */
const copyToClipboard = async (text) => {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      try {
        await navigator.clipboard.writeText(text);
        showToast();
        return;
      } catch (e) {}
    }
    const tmp = document.createElement('textarea');
    tmp.value = text;
    tmp.style.position = 'fixed';
    tmp.style.top = '-1000px';
    document.body.appendChild(tmp);
    tmp.select();
    document.execCommand('copy');
    document.body.removeChild(tmp);
    showToast();
};
  
/* === 互動邏輯 === */
// 測驗顯示切換
[...document.querySelectorAll('input[name="quiz"]')].forEach((r) => {
    r.addEventListener('change', (e) => {
      document.getElementById('lifeDesc').classList.toggle('hidden', e.target.value !== 'life');
      document.getElementById('mbtiInput').classList.toggle('hidden', e.target.value !== 'mbti');
    });
});
  
// 主石子選單邏輯
const subMap = {
    貔貅: ['月光石貔貅', '拉長石貔貅', '紫牙烏貔貅', '黑金骨幹貔貅'],
    貓咪: ['白色貓咪', '黑色貓咪'],
    兔子: ['月光石兔子', '橙月光兔子'],
};
  
const mainStone = document.getElementById('mainStone');
mainStone?.addEventListener('change', (e) => {
    const key = e.target.value;
    const subDiv = document.getElementById('subStone');
    const subSelect = document.getElementById('subOptions');
    subSelect.innerHTML = '';
    if (subMap[key]) {
      subDiv.classList.remove('hidden');
      subMap[key].forEach((opt) => {
        const o = document.createElement('option');
        o.value = opt;
        o.textContent = opt;
        subSelect.appendChild(o);
      });
    } else {
      subDiv.classList.add('hidden');
    }
});
  
/* 生成分享文字 */
const getCheckedValues = (sel) => [...document.querySelectorAll(sel)].filter((el) => el.checked).map((el) => el.value);
  
const generateBtn = document.getElementById('generateTextBtn');
const shareArea = document.getElementById('shareText');
  
generateBtn?.addEventListener('click', () => {
    const summary = [
      `【款式】 ${getCheckedValues('input[name="styles"]:checked').join(', ')}`,
      `【測驗】 ${document.querySelector('input[name="quiz"]:checked').value}`,
      document.querySelector('input[name="quiz"]:checked').value === 'mbti' ? `【MBTI】 ${document.querySelector('input[name="mbtiType"]').value}` : null,
      `【網站範例截圖描述】 ${document.getElementById('siteScreenshot').value}`,
      `【喜歡色系】 ${document.querySelector('input[name="colors"]').value}`,
      `【喜歡水晶】 ${document.querySelector('input[name="crystals"]').value}`,
      `【象徵意義】 ${document.querySelector('input[name="symbolism"]').value}`,
      `【主石】 ${document.querySelector('select[name="mainStone"]').value}`,
      `【子款式】 ${document.getElementById('subOptions')?.value || ''}`,
      `【飾質】 ${document.querySelector('select[name="metalType"]').value}`,
      `【結尾扣】 ${getCheckedValues('input[name="clasp"]:checked').join(', ')}`,
      `【預算】 ${document.querySelector('input[name="budgetMin"]').value} – ${document.querySelector('input[name="budgetMax"]').value}`,
      `【送禮】 ${document.querySelector('select[name="isGift"]').value}`,
      `【時間需求】 ${document.querySelector('input[name="deadline"]').value}`,
      `【其他備註】 ${document.querySelector('textarea[name="notes"]').value}`,
    ].filter(Boolean).join('\n');
  
    shareArea.value = summary;
    copyToClipboard(summary);
});
