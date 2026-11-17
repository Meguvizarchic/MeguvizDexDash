#!/usr/bin/env python3
"""Synthetic inputs and a synthetic catalog for the structural audit (MDD-051).

HostLab's 27 FEATURE rules look for classes of one application by name. That application is not part of this
repository, and neither is the operator's `audit_catalog.json`. This module builds small DEX files and APKs that
contain classes with the names the frozen rules look for (the literals in `native_rules.py`) and classes with
neutral names for what the catalog would supply, shaped so that the rules answer FOUND, PARTIAL or MISSING on
purpose, and writes a catalog of the same shape that names only the neutral classes.

Nothing here is a copy of the application's code: each class has just the members a rule asks about. Every input
is deterministic; `write_inputs` returns the SHA-256 of each file, and the goldens record those digests.

Worlds:

* `full`      most rules FOUND, several with the exact member lists they check; two DEX members.
* `partial`   the four rules that can answer PARTIAL do so; the others FOUND or MISSING; one DEX member.
* `sparse`    decoys only, so every rule answers MISSING; a raw DEX, not an APK.
* `duplicate` `full` plus a second definition of one class: the audit itself refuses (UnsupportedAudit).
* `badsig`    `full` plus a Signature the audit does not accept: the audit itself refuses (UnsupportedAudit).
* `badrefs`   `full` plus a method the engine cannot read the code of: the engine opens the dataset with layer
              issues and refuses what needs those layers (not a business verdict, not an audit refusal).
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from structural_dex import (ACC_ABSTRACT, ACC_ENUM, ACC_FINAL, ACC_INTERFACE, ACC_PRIVATE, ACC_PUBLIC,  # noqa: E402
                            ACC_STATIC, ACC_SYNTHETIC, ClassSpec, FieldSpec, MethodSpec, build_apk, build_dex, desc)

CATALOG_DIR = HERE / "structural-catalog"
JAVA_STAND_IN = (b"// Synthetic stand-in for HostCompatibilityAudit.java (MDD-051). The real file is the operator's.\n"
                 b"// native_rules.py compares its SHA-256 with reference_sha256 in audit_catalog.json.\n")
STATIC = ACC_STATIC


def klass(name, extends="java.lang.Object", implements=(), access=ACC_PUBLIC, fields=(), methods=(), sig=None):
    return ClassSpec(desc(name), access, desc(extends) if extends else None, tuple(desc(i) for i in implements),
                     list(fields), list(methods), sig)


def iface(name, methods=(), extends="java.lang.Object"):
    return klass(name, extends=extends, access=ACC_PUBLIC | ACC_INTERFACE | ACC_ABSTRACT, methods=methods)


def fld(name, type_, access=ACC_PUBLIC, sig=None):
    return FieldSpec(name, desc(type_), access, sig)


def mth(name, ret="void", args=(), access=ACC_PUBLIC, sig=None, code=None):
    return MethodSpec(name, desc(ret), tuple(desc(a) for a in args), access, sig, code)


def gen(raw, *args):
    """`java.util.List<Lsyn/Item;>;` for ('java.util.List', 'syn.Item')."""
    return "L" + raw.replace(".", "/") + "<" + "".join("L" + a.replace(".", "/") + ";" for a in args) + ">;"


def ctor(*args, sig=None, access=ACC_PUBLIC):
    return mth("<init>", "void", args, access, sig)


# ---- the catalog -----------------------------------------------------------------------------------------

LISTS = {
    "run.blockCandidates": ["syn.cat.UpdateGate"],
    "run.qualityCandidates": ["syn.cat.QualityPrefs", "syn.cat.QualityAlt"],
    "auditCommentCopy.lowOwners": ["syn.cat.CopyLow"],
    "auditCommentCopy.highOwners": ["syn.cat.CopyHigh"],
    "auditHomeTopBar.baseOwners": ["syn.cat.TopBarBase"],
    "auditFullNumber.owners": ["syn.cat.NumberFmt", "kntr.base.localization.NumberFormat_androidKt"],
    "auditFullNumber.names": ["formatNumber", "format"],
    "auditHomeRecommend.responses": ["syn.cat.RecResponse"],
    "auditHomeTabs.owners": ["syn.cat.TabsOwner"],
    "auditMineComponents.groupOwners": ["syn.cat.MineGroup"],
    "auditMineComponents.itemOwners": ["syn.cat.MineItem"],
    "auditStory.booleanNames": ["isStory", "isLive"],
    "auditSplash.owners": ["syn.cat.SplashResponse"],
    "auditSplash.names": ["getSplashList", "getList"],
    "auditBottomBar.owners": ["syn.cat.BottomBar"],
    "auditCommentData.replyOwners": ["syn.reply.Reply"],
    "auditCommentTopology.replyGetters": ["getContent", "getMember", "getRpid"],
    "auditCommentTopology.detailSetters": ["setOid", "setType"],
    "auditCommentSection.services": ["syn.cat.CommentService"],
}


def catalog() -> dict:
    owners = sorted({name for values in LISTS.values() for name in values if "." in name and name[0].islower()
                     and name.startswith(("syn.", "kntr."))})
    owners += [f"syn.pad.P{index:03d}" for index in range(100)]  # absent names: the prefetch runs in several batches
    return {"reference_sha256": hashlib.sha256(JAVA_STAND_IN).hexdigest(), "owners": owners, "lists": LISTS}


def write_catalog(directory: Path) -> None:
    (directory / "analysis").mkdir(parents=True, exist_ok=True)
    (directory / "analysis/HostCompatibilityAudit.java").write_bytes(JAVA_STAND_IN)
    (directory / "analysis/audit_catalog.json").write_text(
        json.dumps(catalog(), indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


# ---- recipes: the classes behind each rule -----------------------------------------------------------------

def block_update(found=True):
    info = "tv.danmaku.bili.update.model.BiliUpgradeInfo"
    return [klass(info),
            klass("syn.cat.UpdateGate", methods=[
                mth("check", info, ["android.content.Context"]) if found else mth("check", "void", ["android.content.Context"]),
                mth("stat", info, ["android.content.Context"], ACC_PUBLIC | STATIC),
                mth("wrongArgs", info, ["java.lang.String"])])]


def player_default_quality(semantic=True, structural=True):
    def quality(label):
        return [("const-string", 0, label), ("const4", 1, 3), ("return", 1)]
    if structural:
        members = [mth("a", "int", code=quality("quality settings:" if semantic else "unrelated")),
                   mth("getDefaultQuality", "int"),
                   mth("other", "int", code=quality("pref_player_mediaSource_quality_wifi_key"))]
    else:
        members = [mth("other", "int", code=quality("pref_player_mediaSource_quality_wifi_key" if semantic else "unrelated"))]
    members += [mth("c", "int", ["int"]), mth("abstractQuality", "int", access=ACC_PUBLIC | ACC_ABSTRACT)]
    return [klass("syn.cat.QualityPrefs", access=ACC_PUBLIC | ACC_ABSTRACT, methods=members),
            klass("syn.cat.QualityAlt", methods=[mth("c", "int"), mth("d", "int")])]


def comment_free_copy(high=True, low=True):
    out = []
    if high:
        out += [klass("syn.cat.CopyHigh", fields=[fld("item", "syn.cmt.CommentItem")],
                      methods=[mth("copy", "void", ["syn.cat.ViewHolder"]), mth("tooMany", "void", ["int"] * 6),
                               mth("none", "void"), mth("statics", "void", ["syn.cat.ViewHolder"], ACC_PUBLIC | STATIC)],
                      sig=gen("java.lang.Object", "syn.cmt.CommentItem")),
                klass("syn.cmt.CommentItem"),
                klass("syn.cat.ViewHolder", fields=[fld("text", "android.widget.TextView"), fld("other", "java.lang.Object")])]
    if low:
        out += [klass("syn.cat.CopyLow", methods=[mth("o0", "void"), mth("q0", "void", ["int"]), mth("p0", "void")])]
    return out


def description_free_copy(found=True):
    out = [klass("tv.danmaku.bili.videopage.common.widget.view.ExpandableTextView", extends="android.widget.TextView")]
    string = "java.lang.String"
    if found:
        out += [klass("com.bilibili.ship.theseus.ugc.intro.ugcheadline.UgcHeadlineService$b",
                      methods=[mth("c", "void", [string, "boolean"]), mth("w", "void", ["boolean", string]),
                               mth("o", "void", [string, "boolean"])])]
    return out


def home_top_bar(game=True, base=True, switch=True, words=False):
    out = []
    if game:
        out += [klass("com.bilibili.lib.homepage.startdust.menu.a",
                      methods=[mth("inflate", "void", ["android.view.Menu", "android.view.MenuInflater"]),
                               mth("inflate2", "void", ["android.view.Menu"])])]
    if base:
        out += [klass("syn.cat.TopBarBase",
                      fields=([fld("switcher", "com.bilibili.lib.homepage.widget.SwitchTextView")] if switch else []),
                      methods=[mth("onViewCreated", "void", ["android.view.View", "android.os.Bundle"]),
                               mth("onViewCreated", "void", ["android.view.View"])])]
    if words:
        out += [klass("tv.danmaku.bili.ui.main2.MainFragment",
                      methods=[mth("setWords", "void", ["com.bilibili.app.comm.list.common.api.b"])])]
    return out


def mine_entry(found=True):
    fragment = "tv.danmaku.bili.ui.main2.mine.HomeUserCenterFragment"
    return [klass(fragment,
                  fields=[fld("groups", "java.util.List", ACC_PRIVATE), fld("sharedGroups", "java.util.List", ACC_PRIVATE | STATIC),
                          fld("manager", "tv.danmaku.bili.ui.main2.mine.modularvip.MineVipModuleManager", ACC_PRIVATE)]
                  + ([] if found else [fld("secondGroups", "java.util.List", ACC_PRIVATE)]),
                  methods=[mth("build", "void", [fragment, "tv.danmaku.bili.ui.main2.api.AccountMine"], ACC_PUBLIC | STATIC),
                           mth("onResume", "void")]),
            klass(fragment + "$e", methods=[mth("click", "void", ["com.bilibili.lib.homepage.mine.MenuGroup$Item"])]),
            klass(fragment + "$i", methods=[mth("other", "void", ["java.lang.String"])] +
                  ([] if found else [mth("click2", "void", ["com.bilibili.lib.homepage.mine.MenuGroup$Item"])]))]


def mine_vip():
    manager = "tv.danmaku.bili.ui.main2.mine.modularvip.MineVipModuleManager"
    return [klass(manager, fields=[fld("binding", "syn.cat.VipBinding", ACC_PRIVATE), fld("tag", "java.lang.String"),
                                   fld("shared", "syn.cat.VipBinding", STATIC)]),
            iface("androidx.viewbinding.ViewBinding"),
            klass("syn.cat.VipBinding", implements=["androidx.viewbinding.ViewBinding"],
                  methods=[mth("getRoot", "android.widget.LinearLayout")])]


def dynamic_tabs(found=True):
    fragment = "com.bilibili.bplus.followinglist.home.mediator.MediatorFragment"
    return [klass(fragment, methods=[mth("getTabs", "java.util.List", sig="()" + gen("java.util.List", "syn.cat.TabItem")),
                                     mth("setTabs", "void", ["java.util.List"])]),
            klass("syn.cat.TabItem", fields=[fld("a", "java.lang.String"), fld("b", "java.lang.String" if found else "int")]),
            klass("com.bilibili.bplus.followinglist.home.mediator.MediatorTabLayout",
                  extends="com.google.android.material.tabs.TabLayout")]


def full_number():
    return [klass("syn.cat.NumberFmt", methods=[
        mth("formatNumber", "java.lang.String", ["long"], ACC_PUBLIC | STATIC),
        mth("format", "java.lang.String", ["java.lang.Float"], ACC_PUBLIC | STATIC)])]


def player_portrait():
    return [klass("com.bilibili.app.gemini.player.widget.story.GeminiPlayerFullStoryWidget", extends="android.widget.FrameLayout",
                  methods=[mth("setVisibility", "void", ["int"]), mth("setVisibility", "void", ["boolean"])])]


def player_status_bar():
    return [klass("com.bilibili.ship.theseus.detail.UnitedBizDetailsActivity", extends="android.app.Activity",
                  methods=[mth("onCreate", "void", ["android.os.Bundle"])])]


def home_recommend():
    holder = "com.bilibili.pegasus.PegasusHolderData"
    return [klass(holder, methods=[mth("getHolderType", "java.lang.String")]),
            klass("com.bilibili.pegasus.data.base.BasePegasusData", methods=[mth("getUri", "java.lang.String")]),
            klass("syn.cat.RecBase", methods=[mth("getItems", "java.util.List")]),
            klass("syn.cat.RecResponse", extends="syn.cat.RecBase")]


def video_relate():
    return [klass("com.bapis.bilibili.app.viewunite.v1.Relates", methods=[mth("getCardsList", "java.util.List"),
                                                                           mth("getRelatesList", "java.util.List", ["int"])]),
            klass("com.bapis.bilibili.app.viewunite.common.RelateCard",
                  methods=[mth("getCardCase", "int"), mth("getGoto", "java.lang.String"), mth("getCardType", "void")])]


def home_tabs(found=True):
    arg = gen("java.util.List", "tv.danmaku.bili.ui.main2.resource.Tab" if found else "syn.other.Tab")
    return [klass("syn.cat.TabsOwner", methods=[
        mth("convert", "java.util.List", ["java.util.List"], sig="(" + arg + ")" + gen("java.util.List", "java.lang.String")),
        mth("plain", "java.util.List", ["java.util.List"])])]


def mine_components():
    return [klass("syn.cat.MineGroup", methods=[mth("getItemList", "java.util.List")]),
            klass("syn.cat.MineItem", methods=[mth("getTitle", "java.lang.String")])]


def story_purify():
    detail = "com.bilibili.video.story.StoryDetail"
    return [klass(detail, methods=[mth("isStory", "boolean"), mth("isLive", "int")]),
            klass("com.bilibili.video.story.api.StoryFeedResponse", methods=[mth("getItems", "java.util.List")]),
            klass("com.bilibili.video.story.player.StoryPagerPlayer", methods=[
                mth("submit", "void", ["java.util.List"], sig="(" + gen("java.util.List", detail) + ")V")])]


def splash_ads():
    return [klass("syn.cat.SplashBase", methods=[mth("getSplashList", "java.util.List")]),
            klass("syn.cat.SplashResponse", extends="syn.cat.SplashBase")]


def bottom_bar():
    return [klass("syn.cat.BottomBar", methods=[mth("getTabs", "java.util.List"),
                                                 mth("bind", "void", ["int", "android.widget.TextView"]),
                                                 mth("bind", "void", ["java.lang.String", "android.widget.TextView"])])]


def teenagers_mode():
    return [klass("com.bilibili.app.preferences.TeenagersModeDialogActivity", extends="android.app.Activity",
                  methods=[mth("onCreate", "void", ["android.os.Bundle"])])]


def comment_family():
    """comment_filter, comment_purify, comment_topology and comment_section."""
    string, lst = "java.lang.String", "java.util.List"
    reply = "syn.reply.Reply"
    out = [klass(reply, methods=[mth("getContent", "syn.reply.Content"), mth("getMember", "syn.reply.MemberV2"),
                                 mth("getRpid", "long"), mth("getRepliesList", lst, sig="()" + gen(lst, reply))]),
           klass("com.bapis.bilibili.main.community.reply.v1.Content", methods=[mth("getUrlsList", lst)]),
           klass("com.bapis.bilibili.main.community.reply.v1.MainListReply", methods=[mth("hasQoe", "boolean")])]
    item = "com.bilibili.app.comment3.data.model.CommentItem"
    out += [klass(item, methods=[mth("getId", "long"),
                                 mth("from", item, [reply], ACC_PUBLIC | STATIC),
                                 mth("fromSynthetic", item, [reply], ACC_PUBLIC | STATIC | ACC_SYNTHETIC)]),
            klass("syn.reply.Content", methods=[mth("getMessage", string)]),
            klass("syn.reply.MemberV2$Basic", methods=[mth("getName", string)]),
            klass("syn.reply.DetailListReply", methods=[mth("getRoot", reply), mth("getPaginationReply", "syn.reply.PageReply")]),
            klass("com.bapis.bilibili.pagination.FeedPaginationReply", methods=[mth("getNextOffset", string)]),
            klass("com.bapis.bilibili.pagination.FeedPagination",
                  methods=[mth("newBuilder", "com.bapis.bilibili.pagination.FeedPagination$Builder", access=ACC_PUBLIC | STATIC)]),
            klass("com.bapis.bilibili.pagination.FeedPagination$Builder",
                  methods=[mth("setOffset", "com.bapis.bilibili.pagination.FeedPagination$Builder", [string]),
                           mth("build", "com.bapis.bilibili.pagination.FeedPagination")]),
            klass("syn.reply.DetailListReq",
                  methods=[mth("newBuilder", "syn.reply.DetailListReq$Builder", access=ACC_PUBLIC | STATIC)]),
            klass("syn.reply.DetailListReq$Builder",
                  methods=[mth("setOid", "syn.reply.DetailListReq$Builder", ["long"]),
                           mth("setType", "syn.reply.DetailListReq$Builder", ["long"]),
                           mth("build", "syn.reply.DetailListReq")]),
            klass("syn.reply.ReplyMoss", methods=[mth("detailList", "void", ["syn.reply.DetailListReq", "java.lang.Object"])])]
    # comment_section: a constructor taking List<SectionItem>, an item whose getter returns an enum with a COMMENT constant
    section = "syn.sec.SectionItem"
    out += [klass("syn.cat.CommentService", fields=[fld("items", lst, sig=gen(lst, section))], methods=[
                ctor(lst, sig="(" + gen(lst, section) + ")V"),
                ctor(lst, "java.lang.Object", access=ACC_PUBLIC | ACC_SYNTHETIC)]),
            klass(section, methods=[mth("getType", "syn.sec.SectionType"), mth("getName", string)]),
            klass("syn.sec.SectionType", extends="java.lang.Enum", access=ACC_PUBLIC | ACC_FINAL | ACC_ENUM,
                  fields=[fld("COMMENT", "syn.sec.SectionType", ACC_PUBLIC | STATIC | ACC_FINAL | ACC_ENUM),
                          fld("OTHER", "syn.sec.SectionType", ACC_PUBLIC | STATIC | ACC_FINAL | ACC_ENUM)])]
    return out


def direct_family(game_header=True, game_body=True):
    out = [klass("kntr.app.ad.biz.videodetail.pausedpage.AdPausedPageApi$requestPausedPage$2",
                 methods=[mth("invokeSuspend", "java.lang.Object", ["java.lang.Object"])]),
           klass("com.bilibili.pegasus.holders.bannerv8.V8Banner", extends="com.bilibili.app.comm.list.widget.swiper.SwiperBanner"),
           klass("com.bilibili.app.comm.list.widget.swiper.SwiperBanner", extends="android.widget.FrameLayout",
                 methods=[mth("onAttachedToWindow")]),
           klass("com.bilibili.ship.theseus.united.page.intro.module.merchandise.MerchandiseComponent",
                 methods=[mth("createViewEntry", "android.view.View", ["android.content.Context", "android.view.ViewGroup"])])]
    mention = "com.bapis.bilibili.app.viewunite.common.Mention"
    methods = ([mth("getCardsList", "java.util.List")] if game_body else []) + ([mth("getTitle", "java.lang.String")] if game_header else [])
    out.append(klass(mention, methods=methods or [mth("unrelated")]))
    return out


def call_sites():
    """Repeated calls to protocol classes and to ordinary classes: the multiplicity the call-site statements count."""
    moss = "com.bapis.bilibili.app.FooMoss"

    def call(owner, name, ret="void", args=()):
        return ("invoke", "static", (desc(owner), name, desc(ret), tuple(desc(a) for a in args)), ())

    return [klass(moss, methods=[mth("get", "void", access=ACC_PUBLIC | STATIC),
                                  mth("list", "void", ["java.lang.String"], ACC_PUBLIC | STATIC)]),
            klass("com.bapis.bilibili.app.BarMoss", methods=[mth("serve")]),
            klass("syn.fam.Util", methods=[mth("help", "void", access=ACC_PUBLIC | STATIC)]),
            klass("syn.fam.CallerA", methods=[
                mth("run", "void", access=ACC_PUBLIC | STATIC, code=[call(moss, "get"), call(moss, "get"), call("syn.fam.Util", "help"),
                                                                     ("return-void",)]),
                mth("again", "void", access=ACC_PUBLIC | STATIC, code=[call(moss, "get"), ("return-void",)]),
                mth("quiet", "void", access=ACC_PUBLIC | STATIC, code=[call("syn.fam.Util", "help"), call("syn.fam.Util", "help"),
                                                                       call("syn.fam.Util", "help"), ("return-void",)])])]


def decoys():
    """Classes that look like neighbours of the interesting ones and make no rule true."""
    return [klass("syn.decoy.Alpha", methods=[mth("run"), mth("getItems", "java.util.List")]),
            klass("syn.decoy.Beta", extends="syn.decoy.Alpha", fields=[fld("name", "java.lang.String")]),
            klass("syn.decoy.Gamma", implements=["java.lang.Runnable"], methods=[mth("run")])]


# ---- worlds ------------------------------------------------------------------------------------------------

def _full():
    out = []
    for part in (block_update(), player_default_quality(), comment_free_copy(), description_free_copy(), home_top_bar(),
                 mine_entry(), mine_vip(), dynamic_tabs(), full_number(), player_portrait(), player_status_bar(),
                 home_recommend(), video_relate(), home_tabs(), mine_components(), story_purify(), splash_ads(),
                 bottom_bar(), teenagers_mode(), comment_family(), direct_family(), call_sites(), decoys()):
        out += part
    return out


def _partial():
    out = []
    for part in (block_update(found=False), player_default_quality(semantic=False), comment_free_copy(high=False),
                 description_free_copy(found=False), home_top_bar(game=True, base=False, switch=False),
                 mine_entry(found=False), mine_vip(), dynamic_tabs(found=False), full_number(), player_portrait(),
                 home_recommend(), home_tabs(found=False), mine_components(), story_purify(),
                 direct_family(game_header=False), call_sites(), decoys()):
        out += part
    return out


def _by_dex(classes, count):
    """Deterministic placement: the first class goes to member 0, and so on round the members."""
    members = [[] for _ in range(count)]
    for index, spec in enumerate(sorted(classes, key=lambda c: c.descriptor)):
        members[index % count].append(spec)
    return members


def world(name: str):
    """(list of classes per DEX member, container) for a world. A container is `apk` or `dex`."""
    if name == "full":
        return _by_dex(_full(), 2), "apk"
    if name == "partial":
        return [_partial()], "apk"
    if name == "sparse":
        return [decoys()], "dex"
    if name == "duplicate":
        members = _by_dex(_full(), 2)
        members[1].append(klass("syn.cat.UpdateGate", methods=[mth("other", "void")]))
        return members, "apk"
    if name == "badsig":
        members = _by_dex(_full(), 2)
        for spec in members[0] + members[1]:
            if spec.descriptor == desc("syn.cat.UpdateGate"):
                spec.fields.append(fld("outer", "java.lang.Object", sig="Lsyn/Outer<TT;>.Inner;"))
        return members, "apk"
    if name == "badrefs":
        # `full`, and one method whose code item declares the wrong number of incoming words: the engine opens the
        # dataset but cannot build the code/reference/annotation layers (layer_issues), so relations that need them
        # are refused as incomplete facts, while the metadata and definitions relations still answer
        members = _by_dex(_full(), 2)
        for spec in members[0]:
            if spec.descriptor == desc("syn.decoy.Alpha"):
                spec.methods.append(mth("broken", "void", ["long"], ACC_PUBLIC | STATIC, code=[("return-void",)]))
                spec.methods[-1].ins_words = 1
        return members, "apk"
    raise KeyError(name)


WORLDS = ("full", "partial", "sparse", "duplicate", "badsig", "badrefs")


def build_world(name: str) -> "tuple[str, bytes]":
    members, container = world(name)
    dexes = [build_dex(classes) for classes in members]
    if container == "dex":
        return name + ".dex", dexes[0]
    names = ["classes.dex"] + [f"classes{index + 1}.dex" for index in range(1, len(dexes))]
    return name + ".apk", build_apk(list(zip(names, dexes)))


def write_inputs(directory: Path) -> "dict[str, str]":
    directory.mkdir(parents=True, exist_ok=True)
    digests = {}
    for name in WORLDS:
        filename, data = build_world(name)
        (directory / filename).write_bytes(data)
        digests[filename] = hashlib.sha256(data).hexdigest()
    return digests


def main(argv=None) -> int:
    import argparse
    parser = argparse.ArgumentParser(description="Write the synthetic structural-audit inputs and print their digests.")
    parser.add_argument("directory", type=Path)
    parser.add_argument("--catalog", action="store_true", help="also (re)write conformance/hostlab/structural-catalog")
    args = parser.parse_args(argv)
    if args.catalog:
        write_catalog(CATALOG_DIR)
    print(json.dumps(write_inputs(args.directory), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
