export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // 1. 自动嗅探识别绑定的 R2 存储桶
    let bucket = env.BUCKET || env.MY_BUCKET || env.R2 || env.R2_BUCKET || env.PAN || env.FILES || env.FILE_BUCKET;
    if (!bucket) {
      bucket = Object.values(env).find(v => v && typeof v.list === 'function' && typeof v.get === 'function');
    }

    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, x-admin-auth, Range",
      "Referrer-Policy": "strict-origin-when-cross-origin"
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    function jsonResponse(data, status = 200) {
      return new Response(JSON.stringify(data), {
        status,
        headers: { ...corsHeaders, "Content-Type": "application/json; charset=utf-8" }
      });
    }

    const YANDU_R2_DATA_KEY = "_yandu/study_notes.json";
    const YANDU_R2_AUTH_KEY = "_yandu/auth_config.json";

    // 2. 动态读取管理员密码（优先从 R2 配置文件读取，支持前台直接修改）
    async function getCurrentAdminPassword() {
      if (bucket) {
        try {
          const authObj = await bucket.get(YANDU_R2_AUTH_KEY);
          if (authObj) {
            const config = JSON.parse(await authObj.text());
            if (config && config.password) return String(config.password);
          }
        } catch (_) {}
      }
      return String(env.SECRET_PWD || env.SECRET_TOKEN || env.ADMIN_PWD || "5214");
    }

    async function checkAdminAuth() {
      const currentPwd = await getCurrentAdminPassword();
      const token = request.headers.get("x-admin-auth") || url.searchParams.get("adminAuth");
      return Boolean(token && token === currentPwd);
    }

    /* ==========================================================
       📖 核心 API 路由 (/api/auth/* 与 /api/yandu/*)
    ========================================================== */
    try {
      // 1. 登录验证
      if (url.pathname === "/api/auth/login" && request.method === "POST") {
        let reqData;
        try { reqData = await request.json(); } catch (_) { return jsonResponse({ error: "请求格式不合规" }, 400); }
        const currentPwd = await getCurrentAdminPassword();
        if (reqData.password && String(reqData.password) === currentPwd) {
          return jsonResponse({ success: true, token: currentPwd });
        }
        return jsonResponse({ success: false, error: "管理密码错误" }, 401);
      }

      // 2. 握手鉴权校验
      if (url.pathname === "/api/auth/verify" && request.method === "POST") {
        const isValid = await checkAdminAuth();
        return jsonResponse({ valid: isValid });
      }

      // 3. 前台直接修改管理员密码（持久化存入 R2 专属加密文件）
      if (url.pathname === "/api/auth/change_pwd" && request.method === "POST") {
        if (!bucket) return jsonResponse({ error: "未检测到绑定的 R2 存储桶" }, 500);
        let reqData;
        try { reqData = await request.json(); } catch (_) { return jsonResponse({ error: "参数格式错误" }, 400); }

        const { oldPassword, newPassword } = reqData;
        const currentPwd = await getCurrentAdminPassword();

        if (!oldPassword || String(oldPassword) !== currentPwd) {
          return jsonResponse({ error: "当前原密码输入错误，无法修改" }, 403);
        }

        if (!newPassword || String(newPassword).trim().length < 4) {
          return jsonResponse({ error: "新密码长度不能少于 4 位" }, 400);
        }

        const newPwdStr = String(newPassword).trim();
        await bucket.put(YANDU_R2_AUTH_KEY, JSON.stringify({
          password: newPwdStr,
          updatedAt: new Date().toISOString()
        }), {
          httpMetadata: { contentType: "application/json; charset=utf-8" }
        });

        return jsonResponse({ success: true, newPassword: newPwdStr });
      }

      /* --- 研读笔记业务接口（支持图文富文本存储） --- */
      if (url.pathname.startsWith("/api/yandu/")) {
        if (!bucket) return jsonResponse({ error: "未检测到绑定的 R2 存储桶" }, 500);

        // 读取所有研读数据
        if (url.pathname === "/api/yandu/data" && request.method === "GET") {
          const obj = await bucket.get(YANDU_R2_DATA_KEY);
          if (!obj) return jsonResponse({ success: true, exists: false, data: null });

          const content = await obj.text();
          let parsedData = null;
          try { parsedData = JSON.parse(content); } catch (_) { parsedData = null; }
          return jsonResponse({ success: true, exists: true, data: parsedData });
        }

        // 保存更新笔记（需管理员鉴权）
        if (url.pathname === "/api/yandu/save" && request.method === "POST") {
          const isAuthed = await checkAdminAuth();
          if (!isAuthed) return jsonResponse({ error: "Unauthorized" }, 401);

          let reqData;
          try { reqData = await request.json(); } catch (_) {
            return jsonResponse({ error: "数据格式必须为 JSON" }, 400);
          }

          const { categories, books, notes } = reqData;
          if (!Array.isArray(categories) || !Array.isArray(books) || !Array.isArray(notes)) {
            return jsonResponse({ error: "数据结构必须包含 categories, books 和 notes" }, 400);
          }

          const payload = {
            updatedAt: new Date().toISOString(),
            categories,
            books,
            notes
          };

          await bucket.put(YANDU_R2_DATA_KEY, JSON.stringify(payload), {
            httpMetadata: { contentType: "application/json; charset=utf-8" }
          });

          return jsonResponse({ success: true, updatedAt: payload.updatedAt });
        }
      }

      if (url.pathname.startsWith("/api/")) {
        return jsonResponse({ error: "API Route Not Found" }, 404);
      }

    } catch (err) {
      return jsonResponse({ error: err.message || "服务器内部异常" }, 500);
    }

    return env.ASSETS ? env.ASSETS.fetch(request) : new Response("Not Found", { status: 404 });
  }
};
