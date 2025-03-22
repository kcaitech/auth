import { useI18n } from "vue-i18n"

const baseURL = location.origin

const t = useI18n().t

export const verificationEmailTpl = t("email.verificationEmailTpl").replace(
  /{{.BaseURL}}/g,
  baseURL
)

export const passwordResetEmailTpl = t("email.passwordResetEmailTpl").replace(
  /{{.BaseURL}}/g,
  baseURL
)

export const loginNotificationEmailTpl = t("email.loginNotificationEmailTpl").replace(
  /{{.BaseURL}}/g,
  baseURL
)

