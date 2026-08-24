import { MoonOutlined, SunOutlined } from '@ant-design/icons'
import { Button, Tooltip } from 'antd'
import { useTranslation } from 'react-i18next'
import { useTheme } from './themeContext'

export function ThemeToggle() {
  const { theme, toggleTheme } = useTheme()
  const { t } = useTranslation()
  const isDark = theme === 'dark'
  const label = isDark ? t('theme.switchToLight') : t('theme.switchToDark')
  return (
    <Tooltip title={label}>
      <Button className="theme-toggle" aria-label={label} icon={isDark ? <SunOutlined /> : <MoonOutlined />} onClick={toggleTheme} />
    </Tooltip>
  )
}
