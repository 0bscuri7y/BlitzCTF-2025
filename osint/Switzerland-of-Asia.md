# 🏔️ Switzerland of Asia – BlitzHack 2025 (OSINT, 443 pts)

**Challenge Name:** Switzerland of Asia  
**Category:** OSINT  
**Author:** Zwique  
**Points:** 443  

---

### 📝 Description

> "I love to take photos of this land of beauty and write short reflections on my impressions across different platforms.  
Navigate carefully—one wrong turn, and you might find yourself lost in the maze.  
Keep CMD/CTRL + F handy, but remember: not everything is where it seems."

---

### 🧠 Initial Thoughts

- The phrase **“Switzerland of Asia”** commonly refers to **Kashmir**, but the challenge might intentionally mislead.
- We were provided an image named `beautiful.png`, likely a scenic photo.
- The reference to multiple platforms and navigation suggested we needed to **track the image or author** across the internet.

---

### 🔍 Investigation & Approach

1. **Author's blog**  
   - While exploring the author’s blog, I noticed a Pinterest link. This gave me the idea to search the author’s username on Pinterest [`https://zwique.gitbook.io/zwique_notes/achievements/blog-in-ulaanbaatar`](https://zwique.gitbook.io/zwique_notes/achievements/blog-in-ulaanbaatar).
     
2. **Found Match on Pinterest**  
   - Upon doing so, I found the **exact same image** on a Pinterest post.
   - Scrolled through the **comments** on that post and noticed a suspicious link.

3. **Followed the Trail**  
   - The comment mentioned:  
     `"Zwique Spectacular Landscapes... Altai Tavan Bogd..."`  
   - It contained a **Pastebin URL**:  
     [`https://pastebin.com/HvCVgscd`](https://pastebin.com/HvCVgscd)

4. **Retrieved the Flag**  
   - Opened the link and found the flag in plain text.

---

### 🏁 Flag

Blitz{ALTa1_TaVAn_B0Gd_Mongolia}

---

### 🌍 Background

- The flag refers to **Altai Tavan Bogd**, a national park in Mongolia.
- The challenge title was likely a red herring — it’s not Kashmir or India, but **Altai Mountains** in Central Asia.
- The name means “Five Holy Peaks of the Altai,” and the tallest peak is Khüiten Peak (4,374m).

---

### 👥 Team: 0bscuri7y

- Shadow  

---

 *"I found this chall easy and fun"*
