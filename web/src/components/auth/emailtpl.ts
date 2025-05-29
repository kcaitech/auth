/*
 * Copyright (c) 2025 KCai Technology (https://kcaitech.com)
 * Licensed under the MIT License.
 */

import i18n from "@/locales"

const baseURL = location.origin

const t = i18n.global.t

export const verificationEmailTpl = t("email.verificationEmailTpl").replace(
  /<%BaseURL%>/g,
  baseURL
).replace(/<%/g, "{{.").replace(/%>/g, "}}")

export const passwordResetEmailTpl = t("email.passwordResetEmailTpl").replace(
  /<%BaseURL%>/g,
  baseURL
).replace(/<%/g, "{{.").replace(/%>/g, "}}")

export const loginNotificationEmailTpl = t("email.loginNotificationEmailTpl").replace(
  /<%BaseURL%>/g,
  baseURL
).replace(/<%/g, "{{.").replace(/%>/g, "}}")

