# שרת ה-API של פורטל התלמידים (Express + MongoDB)

## הפעלה מקומית
1. התקינו Node.js (גרסה 20 ומעלה) ו-MongoDB (מקומי או חשבון Atlas).
2. בתיקייה הזו:
   ```
   npm install
   copy .env.example .env     (ב-Mac/Linux: cp .env.example .env)
   ```
3. פתחו את `.env` ומלאו לפחות: `MONGODB_URI` ו-`JWT_SECRET` (הפקודה ליצירת מפתח כתובה בתוך הקובץ).
4. `npm start`
5. בקובץ `portal-v6.html`, בבלוק `CONFIG`, ודאו ש-`BACKEND: 'mongo'` ו-`API_URL` מצביע על השרת (ברירת מחדל: http://localhost:3000). פתחו את ה-HTML בדפדפן רגיל.

## מה נשמר ב-MongoDB
- `users`: אימייל, גיבוב סיסמה (bcrypt), האם אומת.
- `codes`: גיבוב קוד האימות בלבד, תוקף 10 דקות, נמחק אוטומטית.
- `user_data`: נתוני המשתמש (מערכת, משימות, פתקים, ציונים), מסמך לכל מפתח.

## מייל
בלי הגדרות SMTP, קוד האימות מודפס בחלון השרת. עם `DEV_RETURN_CODE=true` (בפיתוח בלבד) הוא גם מוצג בדף.
לשליחה אמיתית מלאו `SMTP_*` ב-`.env` (אפשר ספק עם מסלול חינמי, או Gmail עם סיסמת אפליקציה).

## לפני שמעלים לאינטרנט
- הגדירו `NODE_ENV=production`, `JWT_SECRET` חזק, ו-`CORS_ORIGIN` לכתובת האתר שלכם בלבד.
- השרת חייב לרוץ ב-HTTPS. אם הוא מאחורי פרוקסי (Render וכד'), הוסיפו `TRUST_PROXY=true`.
- ב-Atlas: הוסיפו את כתובת ה-IP של השרת ל-Network Access.
- שומרים את `.env` מחוץ ל-Git.
