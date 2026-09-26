import type { MusicPlayerConfig } from "../types/musicConfig";

// 音乐播放器配置
export const musicPlayerConfig: MusicPlayerConfig = {
	// 是否在导航栏显示音乐播放器入口
	showInNavbar: true,

	// 是否在侧边栏显示音乐播放器组件
	showInSidebar: true,

	// 使用方式："meting" 使用 Meting API，"local" 使用本地音乐列表
	mode: "local",

	// 默认音量 (0-1)
	volume: 0.7,

	// 播放模式：'list'=列表循环, 'one'=单曲循环, 'random'=随机播放
	playMode: "list",

	// 是否显启用歌词
	showLyrics: false,

	// Meting API 配置
	meting: {
		// Meting API 地址
		// 默认使用官方 API，也可以使用自定义 API
		api: "https://api.i-meto.com/meting/api?server=:server&type=:type&id=:id&r=:r",
		// 音乐平台：netease=网易云音乐, tencent=QQ音乐, kugou=酷狗音乐, xiami=虾米音乐, baidu=百度音乐
		server: "netease",
		// 类型：song=单曲, playlist=歌单, album=专辑, search=搜索, artist=艺术家
		type: "playlist",
		// 歌单/专辑/单曲 ID 或搜索关键词
		id: "10046455237",
		// 认证 token（可选）
		auth: "",
		// 备用 API 配置（当主 API 失败时使用）
		fallbackApis: [
			"https://api.injahow.cn/meting/?server=:server&type=:type&id=:id",
			"https://api.moeyao.cn/meting/?server=:server&type=:type&id=:id",
		],
	},

	// 本地音乐配置（当 mode 为 'local' 时使用）
	// 1. 支持传入歌词文件的路径
	// lrc: "/assets/music/lrc/01. Remember.lrc",
	// 2. 或者直接填入歌词字符串内容
	// lrc: "[00:00.00]歌词内容...",
	local: {
		playlist: [
			{
				name: "Remember",
				artist: "",
				url: "/assets/music/01. Remember.m4a",
				cover: "/assets/music/cover/p2928981286.webp",
			},
			{
				name: "星降る海",
				artist: "",
				url: "/assets/music/02. 星降る海.m4a",
				cover: "/assets/music/cover/p2928981286.webp",
			},
			{
				name: "私は、わたしの事が好き。",
				artist: "",
				url: "/assets/music/03. 私は、わたしの事が好き。.m4a",
				cover: "/assets/music/cover/p2928981286.webp",
			},
			{
				name: "ワールドイズマイン (かぐや&月見ヤチヨ ver.) [CPK! Remix]",
				artist: "",
				url: "/assets/music/04. ワールドイズマイン (かぐや&月見ヤチヨ ver.) [CPK! Remix].m4a",
				cover: "/assets/music/cover/p2928981286.webp",
			},
			{
				name: "Ex-Otogibanashi",
				artist: "",
				url: "/assets/music/05. Ex-Otogibanashi.m4a",
				cover: "/assets/music/cover/p2928981286.webp",
			},
			{
				name: "ハッピーシンセサイザ (Cover)",
				artist: "",
				url: "/assets/music/06. ハッピーシンセサイザ (Cover).m4a",
				cover: "/assets/music/cover/p2928981286.webp",
			},
			{
				name: "瞬間、シンフォニー。",
				artist: "",
				url: "/assets/music/07. 瞬間、シンフォニー。.m4a",
				cover: "/assets/music/cover/p2928981286.webp",
			},
			{
				name: "Reply",
				artist: "",
				url: "/assets/music/08. Reply.m4a",
				cover: "/assets/music/cover/p2928981286.webp",
			},
			{
				name: "ray (超かぐや姫！ Version)",
				artist: "",
				url: "/assets/music/09. ray (超かぐや姫！ Version).m4a",
				cover: "/assets/music/cover/p2928981286.webp",
			},
			{
				name: "メルト (かぐや ver.) [CPK! Remix]",
				artist: "",
				url: "/assets/music/10. メルト (かぐや ver.) [CPK! Remix].m4a",
				cover: "/assets/music/cover/p2928981286.webp",
			},
		],
	},
};
