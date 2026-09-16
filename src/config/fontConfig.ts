/**
 * 字体配置（统一入口）
 *
 * 所有字体相关配置都在此文件中定义：
 *   详细用法请参考 Astro 官方文档：https://docs.astro.build/en/guides/fonts
 * - fonts：Astro Font API 字体定义（自动下载、缓存、优化加载）
 * - fontConfig：字体选择与区域覆盖
 *
 * 添加新字体只需编辑本文件：
 * 1. 在下方 fonts 数组中添加字体定义
 * 2. 在 fontConfig.selected 或区域字段中引用对应的 cssVariable
 *
 * 支持的 provider：https://docs.astro.build/en/reference/font-provider-reference/#built-in-providers
 *   "google"     - Google Fonts
 *   "fontsource" - Fontsource
 *   "local"      - 本地字体文件
 *   "bunny"      - Bunny Fonts
 *   "fontshare"  - Fontshare
 *   "npm"        - NPM 包（如 @fontsource/*）
 *
 * 本地字体子集化：在 fontConfig.subsetFonts 中添加对应 cssVariable 的配置，
 * 构建时脚本会自动扫描页面字符并生成轻量 woff2 子集。
 */
import type { FontDefinition, FontSelectionConfig } from "@/types/fontConfig";

// ─── Astro Font API 字体定义 ───────────────────────────────
// 适用于 Astro Font API 的字体配置，支持自动下载、缓存和优化加载
// 本地开发调试的情况下，修改后需要每次重启开发服务器才能生效
export const fontsList: FontDefinition[] = [
	{
		name: "Zen Maru Gothic",
		cssVariable: "--font-zen-maru-gothic",
		provider: "fontsource",
		weights: ["300", "400", "500", "600", "700"],
		styles: ["normal"],
		subsets: ["latin", "cyrillic"],
		fallbacks: ["sans-serif"],
	},
	{
		name: "Inter",
		cssVariable: "--font-inter",
		provider: "fontsource",
		weights: ["300", "400", "500", "600", "700"],
		styles: ["normal"],
		subsets: ["latin", "cyrillic"],
		fallbacks: ["sans-serif"],
	},
	{
		name: "JetBrains Mono",
		cssVariable: "--font-jetbrains-mono",
		provider: "fontsource",
		weights: ["400", "700"],
		styles: ["normal"],
		subsets: ["latin", "cyrillic"],
		fallbacks: [
			"ui-monospace",
			"SFMono-Regular",
			"Menlo",
			"Monaco",
			"Consolas",
			"Liberation Mono",
			"Courier New",
			"monospace",
		],
	},
	// 中文主字体：MiSans（小米开源中文字体，本地字体 + 构建时子集化）
	// 四个字重按语义注册；正文默认字重由 main.css 的 body { font-weight: 500 } 命中 Medium
	{
		name: "MiSans",
		cssVariable: "--font-misans",
		provider: "local",
		options: {
			variants: [
				{
					src: ["./public/assets/fonts/MiSans-Regular.ttf"],
					weight: 400,
					style: "normal",
				},
				{
					src: ["./public/assets/fonts/MiSans-Medium.ttf"],
					weight: 500,
					style: "normal",
				},
				{
					src: ["./public/assets/fonts/MiSans-Demibold.ttf"],
					weight: 600,
					style: "normal",
				},
				{
					src: ["./public/assets/fonts/MiSans-Bold.ttf"],
					weight: 700,
					style: "normal",
				},
			],
		},
		fallbacks: [
			"PingFang SC",
			"Microsoft YaHei",
			"Noto Sans CJK SC",
			"sans-serif",
		],
	},
	// 中文标题字体：MiSans Light（细字重，用于横幅标题等大字号场景）
	// 文件：public/assets/fonts/MiSans-Light.ttf
	{
		name: "MiSans Light",
		cssVariable: "--font-misans-light",
		provider: "local",
		options: {
			variants: [
				{
					src: ["./public/assets/fonts/MiSans-Light.ttf"],
					weight: 300,
					style: "normal",
				},
			],
		},
		fallbacks: [
			"PingFang SC",
			"Microsoft YaHei",
			"Noto Sans CJK SC",
			"sans-serif",
		],
	},
	// ─── 本地字体示例 ───
	// 使用步骤：
	// 1. 将 TTF/OTF/WOFF2 字体文件放在 public/assets/fonts/ 目录下
	// 2. 参考下方配置填写正确的字体信息
	// 3. 在 fontConfig.selected 或区域字段中引用 cssVariable
	{
		name: "GreatVibes Regular 2",
		cssVariable: "--font-greatvibes",
		provider: "local",
		options: {
			variants: [
				{
					src: ["./public/assets/fonts/GreatVibes-Regular-2.otf"],
				},
			],
		},
		fallbacks: ["sans-serif"],
	},
];

// ─── 字体选择与区域覆盖 ─────────────────────────────────────
export const fontConfig: FontSelectionConfig = {
	// 是否启用自定义字体功能
	enable: true,
	// 当前选择的字体 CSS 变量名（对应上方 fonts 中的 cssVariable）
	// 使用 "system" 表示系统字体（不加载任何自定义字体）
	selected: ["--font-misans"],

	// 各区域独立字体设置（填写上方 fonts 中的 cssVariable，留空则使用全局 selected 字体）
	// 例如：bannerTitleFont: "--font-inter", 表示主页横幅主标题使用 Inter 字体
	// 主页横幅主标题字体（MiSans Light 细字重，大字号更精致）
	bannerTitleFont: "--font-misans-light",
	// 主页横幅副标题字体（副标题为中文诗句，同样用 Light）
	bannerSubtitleFont: "--font-misans-light",
	// 导航栏标题字体
	navbarTitleFont: "",
	// 代码块字体（用于代码高亮和等宽字体场景）
	codeFont: "--font-jetbrains-mono",

	// 本地字体子集化配置（构建时由 scripts/subset-fonts.ts 处理）
	// key 为 fonts 数组中对应的 cssVariable，value 为子集化选项
	subsetFonts: {
		"--font-misans": {
			// 额外包含的字符（覆盖评论、Bangumi 等动态内容）
			extraChars: "",
		},
		"--font-misans-light": {
			// 横幅副标题由打字机效果从内联 script 中取词渲染，子集化脚本
			// 收集字符时会剥掉 script，这里手动补全全部诗句，避免缺字回退到系统字体
			extraChars:
				"你可曾见过比黄金更明亮的梦，可曾记得如何去恨如何去爱。夕暮的云消失在渐落的黄昏间，缠绵的晚风总是会将轻烟吹散；岁月不停奔流，旧日再无回首；也许你还记得，也许你已忘却？可你知道，总有人要将灯点亮——哪怕是在雪原，哪怕是在边乡！",
		},
		"--font-greatvibes": {
			// 额外包含的字符
			extraChars: "",
		},
	},
};
