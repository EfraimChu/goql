package astdata

import (
	"encoding/json"
	"fmt"
	"github.com/TwiN/go-color"
	"github.com/emirpasic/gods/sets/hashset"
	"github.com/gobeam/stringy"
	"io/ioutil"
	"regexp"
	"strings"
	"testing"
	"unicode"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPackage(t *testing.T) {
	p, err := ParsePackage("fixture")
	require.NoError(t, err)
	assert.Equal(t, p.Path(), "fixture")
	assert.Equal(t, p.Name(), "fixture")

	_, err = translateToFullPath("invalid_path")
	assert.Error(t, err)
	_, err = translateToFullPath("not/exists/package")
	assert.Error(t, err)

	p = &Package{}

	f1, err := ParseFile(testArrr, p)
	require.NoError(t, err)
	f2, err := ParseFile(testFunc, p)
	require.NoError(t, err)
	f3, err := ParseFile(testImport, p)
	require.NoError(t, err)
	f4, err := ParseFile(testConst, p)
	require.NoError(t, err)

	p.files = append(p.files, f1, f2, f3, f4)

	assert.Len(t, p.Files(), 4)
	assert.NotEmpty(t, p.Functions())
	assert.NotEmpty(t, p.Variables())
	assert.NotEmpty(t, p.Types())
	assert.NotEmpty(t, p.Imports())
	assert.NotEmpty(t, p.Constants())
}

type CodeGenConf struct {
	genTplFile              bool
	genProxyWMSBasicAPICode bool
	genWMSBasicV2APICode    bool
	genSrcProxyCodeFile     bool
	name                    string
	srcBase                 string
	pbBase                  string
	pbSrcBase               string
	basicV2APICodeBase      string
	basicV2APIPkg           string
	basicV2ViewType         string
	codeBase                string
	proxyStructType         string
	callMngMap              map[string]string
}

func TestBasicPkgs(t *testing.T) {
	packageMap := map[string]*Package{}
	pkgs := []string{
		//view
		"apps/basic/view/vsku",
		"apps/config/view/vsizetype",
		"apps/config/view/vlifecyclerule",
		"apps/config/view/vhighvalue",

		//manager
		"apps/config/manager/msizetype",
		"apps/basic/manager/msku",
		"apps/config/manager/mhighvalue",
		"apps/config/manager/mlifecyclerule",

		//repo
		"apps/basic/service/ssku",
		"apps/basic/service/ssku/sskuexport",
	}

	for _, pkg := range pkgs {
		err := ParsePackage2(packageMap, pkg, true)
		if err != nil {
			t.Error(err.Error())
		}
	}

	importPkgs := []string{}
	for _, pkg := range pkgs {
		pkgObj := packageMap[pkg]
		if pkgObj != nil {
			println(fmt.Sprintf("pkg %v ok ", pkgObj.Name()))
		}
		for _, i := range pkgObj.Imports() {
			pkgName := i.Path()
			if strings.Contains(pkgName, "wms-v2") {
				importPkgs = append(importPkgs, pkgName)
			}
		}
	}

	println(ToPrettyJSON(uniqSlice(importPkgs...)))

	println("done")

}

func TestWMSV2(t *testing.T) {
	packageMap := map[string]*Package{}
	//genConf := getMsizeConf()
	genConf := getMHighbvalueConf()
	//genConf.genTplFile = true
	//genConf.genProxyWMSBasicAPICode = true
	//genConf.genWMSBasicV2APICode = true
	genConf.genSrcProxyCodeFile = true
	err := ParsePackage2(packageMap, genConf.name, true)
	if err != nil {
		t.Error(err.Error())
	}
	p := packageMap[genConf.name]
	pcode := parsePCode(p)

	err = parsePbStructs(genConf.pbSrcBase, pcode, packageMap)
	if err != nil {
		t.Error(err.Error())
	}

	//tpl
	if genConf.genTplFile {
		err = genProxyAPIPbTpl(genConf.pbBase, pcode, packageMap)
		if err != nil {
			t.Error(err.Error())
		}
		extLines := []string{"message MapItem{\n  optional string m_key = 1;\n  optional string m_value = 2;\n  optional string m_type = 3;\n}\nmessage PageInItem{\n  optional  int64  Pageno = 1;       //页码\n  optional  int64     count = 2 ;    // 数量\n  optional  string  order_by = 3;    // 为空字符串 代表不需要排序\n  optional  bool  is_get_total = 4;  // 为False代表不需要获取总数\n}"}

		pcode.ouStructTplDbsMaps["entity"] = append(pcode.ouStructTplDbsMaps["entity"], extLines...)

		err = genTplFile(genConf.pbBase, pcode)
		if err != nil {
			t.Error(err.Error())
		}
	}

	if genConf.genProxyWMSBasicAPICode {
		//wmsbasic api
		err = genProxyAPICodeFile(genConf.codeBase, genConf.pbSrcBase, packageMap, pcode)
		if err != nil {
			t.Error(err.Error())
		}
	}

	if genConf.genWMSBasicV2APICode {
		//wmsbasic api
		pbPkg := packageMap[genConf.pbSrcBase]
		err = genBasicV2APICodeFile(genConf.basicV2APIPkg, genConf.basicV2ViewType, genConf.basicV2APICodeBase, pbPkg, pcode, packageMap)
		if err != nil {
			t.Error(err.Error())
		}
	}

	if genConf.genSrcProxyCodeFile {
		err = genSrcProxyCodeFile(genConf, pcode)
		if err != nil {
			t.Error(err.Error())
		}
	}
	//genWMSV2ProxyPB(p)
	//genWMSV2ProxyAPI(p)
	//genWMSV2ProxyTestAPI(p)
	//genBasicAPI(p)

}

func getMsizeConf() *CodeGenConf {
	var genConf = &CodeGenConf{
		genTplFile:              false,
		genProxyWMSBasicAPICode: false,
		genWMSBasicV2APICode:    true,
		genSrcProxyCodeFile:     false,
		name:                    "apps/config/manager/msizetype",
		srcBase:                 "/Users/yunfeizhu/Code/golang/wms-v2/apps/config/manager/msizetype",
		codeBase:                "/Users/yunfeizhu/Code/golang/wms-v2/apps/wmslib/wmsbasic",
		pbBase:                  "/Users/yunfeizhu/Code/golang/wmsv2-basic-v2-protobuf/apps/basic/pbbasicv2",
		pbSrcBase:               "apps/basic/pbbasicv2/pbmsizetype",
		basicV2APICodeBase:      "/Users/yunfeizhu/Code/golang/wmsv2-basic-v2/apps/config/view/vsizetype",
		basicV2APIPkg:           "vsizetype",
		basicV2ViewType:         "SizeTypeView",
	}
	return genConf
}

func getMHighbvalueConf() *CodeGenConf {
	callMngMap := map[string]string{
		"HighValueManager": "highValueManager",
		//"TaskSizeTypeManager": "tasksizeTypeManger",
	}
	var genConf = &CodeGenConf{
		genTplFile:              false,
		genProxyWMSBasicAPICode: false,
		genWMSBasicV2APICode:    false,
		genSrcProxyCodeFile:     false,
		name:                    "apps/config/manager/mhighvalue",
		srcBase:                 "/Users/yunfeizhu/Code/golang/wms-v2/apps/config/manager/mhighvalue",
		codeBase:                "/Users/yunfeizhu/Code/golang/wms-v2/apps/wmslib/wmsbasic",
		pbBase:                  "/Users/yunfeizhu/Code/golang/wmsv2-basic-v2-protobuf/apps/basic/pbbasicv2",
		pbSrcBase:               "apps/basic/pbbasicv2/pbmhighvalue",
		basicV2APICodeBase:      "/Users/yunfeizhu/Code/golang/wmsv2-basic-v2/apps/config/view/vhighvalue",
		basicV2APIPkg:           "vhighvalue",
		basicV2ViewType:         "HighValueConfigView",
		proxyStructType:         "HighValueManager",
		callMngMap:              callMngMap,
	}
	return genConf
}

func parsePbStructs(pbSrcBase string, pcode *PCode, packageMap map[string]*Package) error {

	//module := pcode.p.name
	//pkgPbDir := "pb" + module
	////tpl := base + "/" + pkgPbDir
	////tplCommon := base + "/pbcommon"
	//pkgBase := "git.garena.com/shopee/bg-logistics/tianlu/wms-protobuf/apps/basic/pbbasicv2"
	//importPkgBase := "apps/basic/pbbasicv2"
	//goPkgPath := fmt.Sprintf("%s/%s", pkgBase, pkgPbDir)
	//importDtoPkg := fmt.Sprintf("%s/%s/%s_dto.tpl.proto", importPkgBase, pkgPbDir, module)
	//importCommonPkg := fmt.Sprintf("%s/%s/entity_entity.tpl.proto", importPkgBase, pkgPbDir)

	err := ParsePbPackage2(packageMap, pbSrcBase)
	if err != nil {
		return err
	}
	return nil
}

func genProxyAPICodeFile(base string, pbsrcBase string, packageMap map[string]*Package, pcode *PCode) error {
	filePre := base + "/" + pcode.p.name
	pbSrcPkg := packageMap[pbsrcBase]

	packageHead := "package wmsbasic"
	apiFiles := []string{packageHead}
	var basicAPISign []string
	for _, sign := range pcode.basicAPIDefMap {
		basicAPISign = append(basicAPISign, sign)
	}
	apiFiles = append(apiFiles, buildPackageProxyBasicAPI(pcode.p, basicAPISign)...)
	err := ioutil.WriteFile(filePre+"_basic_api.go", []byte(strings.Join(apiFiles, "\n")), 0644)
	if err != nil {
		return err
	}

	dtoFiles := []string{packageHead}
	dtoFiles = append(dtoFiles, pcode.proxySrcPkgAPIStructs...)
	err = ioutil.WriteFile(filePre+"_basic_dto.go", []byte(strings.Join(dtoFiles, "\n")), 0644)
	if err != nil {
		return err
	}

	pkgName := pcode.p.name
	pkgApiDesign := pcode.genProxyAPIStructDefAndConstruct()
	receiverPrex := fmt.Sprintf("func (m *%sBasicAPI)", upFirstChar(pkgName))
	var basicAPIProxyBodys string
	for _, basicapi := range pcode.basicAPIPbsMap {

		paramSignStr := basicapi.api.methodReqSign()
		returnSign := basicapi.api.methodReturnSign()
		head := fmt.Sprintf("%s%s (%s)%s {", receiverPrex, basicapi.api.Method, paramSignStr, returnSign)
		body := basicapi.api.proxyBasicFuncBody(pbSrcPkg, packageMap)

		basicAPIProxyBodys += head + "\n" + body
		println(head, "\n", body)

	}

	dtoFiles = []string{"package wmsbasic", pkgApiDesign, basicAPIProxyBodys}
	err = ioutil.WriteFile(filePre+"_basic_api_impl.go", []byte(strings.Join(dtoFiles, "\n")), 0644)
	if err != nil {
		return err
	}

	var endpoints = []string{}
	endpoints = append(endpoints, fmt.Sprintf("// %s endpoint", pcode.p.name))
	endpoints = append(endpoints, "var (")
	for _, api := range pcode.basicAPIPbsMap {
		endpoints = append(endpoints, fmt.Sprintf("%s WmsBasicApi = \"%s\"", api.api.endpointEnum(), api.Path))
	}
	endpoints = append(endpoints, ")")

	dtoFiles = []string{"package wmsbasic"}
	dtoFiles = append(dtoFiles, endpoints...)
	err = ioutil.WriteFile(filePre+"_basic_endpoint.go", []byte(strings.Join(dtoFiles, "\n")), 0644)
	if err != nil {
		return err
	}
	return nil
}

func genBasicV2APICodeFile(pkgName string, basicV2ViewType string, base string, pbSrcPkg *Package, pcode *PCode, packageMap map[string]*Package) error {
	//callMngMap := map[string]string{
	//	"SizeTypeManager":     "sizeTypeManger",
	//	"TaskSizeTypeManager": "tasksizeTypeManger",
	//}
	callMngMap := map[string]string{
		"HighValueManager": "highValueManager",
		//"TaskSizeTypeManager": "tasksizeTypeManger",
	}
	module := pcode.p.name
	filePre := base + "/" + module

	packageHead := fmt.Sprintf("package %s", pkgName)
	apiFiles := []string{packageHead}

	var apis []string
	apis = append(apis, fmt.Sprintf("func init%sProxyHandler(router *wrapper.BasicRouterWrapper, view *HighValueConfigView){", upFirstChar(module)))
	for _, basicapi := range pcode.basicAPIPbsMap {

		routerMethod := basicapi.ProxyOpenapiMethod()
		apiPath := basicapi.Path
		viewMethod := basicapi.api.endpointEnum()
		pbReq := basicapi.api.apiPbReqType()

		handler := fmt.Sprintf("router.%s(\"%s\", view.%s, &%s{})", routerMethod, apiPath, viewMethod, pbReq)
		apis = append(apis, handler)
	}
	apis = append(apis, "}")

	apiFiles = append(apiFiles, apis...)

	err := ioutil.WriteFile(filePre+"_proxy_handler.go", []byte(strings.Join(apiFiles, "\n")), 0644)
	if err != nil {
		return err
	}

	basicAPIImps := []string{
		packageHead,
	}
	for _, basicapi := range pcode.basicAPIPbsMap {
		receiver := basicapi.api.ReceiverName
		curReceiver := callMngMap[receiver]
		if strings.Contains(receiver, "Proxy") {
			continue
		}
		funcs := []string{}
		viewMethod := basicapi.api.endpointEnum()
		sign := fmt.Sprintf("func (v *%s) %s(ctx context.Context, header *wrapper.ReqHeader, request interface{}) (interface{}, *wmserror.WMSError) {", basicV2ViewType, viewMethod)
		funcs = append(funcs, sign)

		//大于的请求，才需要解析req
		if len(basicapi.ReqFields) > 1 {
			funcs = append(funcs, fmt.Sprintf("req := request.(*%s)", basicapi.api.apiPbReqType()))
		}
		paramLines := []string{}

		//for _, field := range basicapi.ReqFields {
		//	if field.isContext() {
		//		continue
		//	}
		//	paramLines = append(paramLines, field.defTypeSign())
		//}

		//structItemLines = basicapi.invokeAlias()

		paramLines = append(paramLines, "")
		funcs = append(funcs, paramLines...)

		_, lines := basicapi.api.genBasicToWMSV2PreItemDefLines(pbSrcPkg, packageMap)
		funcs = append(funcs, lines...)

		method := basicapi.api.Method
		invokeParamStr := strings.Join(basicapi.viewInvokeAlias(), ",")
		invokeRetStr := strings.Join(basicapi.api.apiRets(), ",")

		callLine := fmt.Sprintf(" %s:= v.%s.%s(%s)", invokeRetStr, curReceiver, method, invokeParamStr)
		if len(basicapi.api.apiPbRets()) == 1 && basicapi.api.genBasicV2Err {
			callLine = strings.ReplaceAll(callLine, ":", "")
		}
		handlerErr := basicapi.viewHandlerErr()
		funcs = append(funcs, callLine)
		funcs = append(funcs, handlerErr)

		//convert to
		//convert
		for i, retType := range basicapi.api.Resp {
			if retType == "*wmserror.WMSError" {
				continue
			}
			if isNormalType(retType) {
				continue
			}
			originRet := fmt.Sprintf("ret%v", i+1)
			val := originRet
			var def string
			pbType := toPbType(retType, nil)
			if strings.Contains(retType, "[]") {
				val += "Items"
				def = fmt.Sprintf("%v:=[]*pb%s.%s{}", val, module, pbType)
			} else {
				val += "Item"
				def = fmt.Sprintf("%v:=&pb%s.%s{}", val, module, pbType)
			}
			funcs = append(funcs, def)
			copyJson := `		if jsErr := copier.Copy(%s,%s); jsErr != nil {
			return nil, wmserror.NewError(constant.ErrJsonDecodeFail, jsErr.Error())
		}`
			if strings.Contains(def, "[]") {
				funcs = append(funcs, fmt.Sprintf(copyJson, originRet, "&"+val))
			} else {
				funcs = append(funcs, fmt.Sprintf(copyJson, originRet, "&"+val))
			}
		}

		if len(basicapi.api.Resp) == 1 {
			funcs = append(funcs, fmt.Sprintf("resp := &%s{}", basicapi.api.apiPbRespType()))
		} else {
			funcs = append(funcs, fmt.Sprintf("resp := &%s{", basicapi.api.apiPbRespType()))
			for i, retType := range basicapi.api.Resp {
				if retType == "*wmserror.WMSError" {
					continue
				}
				val := fmt.Sprintf("ret%v", i+1)
				funcs = append(funcs, fmt.Sprintf("Ret%v:%s,", i+1, convertToPbType(retType, val)))
			}
			funcs = append(funcs, "}")
		}
		funcs = append(funcs, "return resp,nil")
		funcs = append(funcs, "}")

		basicAPIImps = append(basicAPIImps, funcs...)
	}

	err = ioutil.WriteFile(filePre+"_proxy_handler_impl.go", []byte(strings.Join(basicAPIImps, "\n")), 0644)
	if err != nil {
		return err
	}
	println(strings.Join(apiFiles, "\n"))
	println(strings.Join(basicAPIImps, "\n"))

	return nil
}

type ItemType string

func (i ItemType) IsInnerStruct() bool {
	itemTypeStr := string(i)
	return !strings.Contains(itemTypeStr, ".") &&
		!strings.EqualFold(itemTypeStr, "string") &&
		!strings.EqualFold(itemTypeStr, "int64") &&
		!strings.Contains(itemTypeStr, "map[string]")
}

func (i ItemType) IsOuterStruct() bool {
	itemTypeStr := string(i)
	return strings.Contains(itemTypeStr, ".")
}

func (i ItemType) String() string {
	return string(i)
}
func genProxyAPIPbTpl(base string, pcode *PCode, packageMap map[string]*Package) error {
	module := pcode.p.name
	pkgPbDir := "pb" + module
	//tpl := base + "/" + pkgPbDir
	//tplCommon := base + "/pbcommon"
	//pbBase := "/Users/yunfeizhu/Code/golang/wms-protobuf/apps/basic/pbbasicv2"
	pkgBase := "git.garena.com/shopee/bg-logistics/tianlu/wmsv2-basic-v2-protobuf/apps/basic/pbbasicv2"
	importPkgBase := "apps/basic/pbbasicv2"
	goPkgPath := fmt.Sprintf("%s/%s", pkgBase, pkgPbDir)
	importDtoPkg := fmt.Sprintf("%s/%s/%s_dto.tpl.proto", importPkgBase, pkgPbDir, module)
	importCommonPkg := fmt.Sprintf("%s/%s/entity_entity.tpl.proto", importPkgBase, pkgPbDir)

	//
	//tplHead := "syntax = \"proto2\";"
	//innerCommonStructs := []string{}
	//for _, pb := range pcode.basicAPIPbs {
	//	inStructs := pb.api.genInnerDefPkgStructs()
	//	innerCommonStructs = append(innerCommonStructs, inStructs...)
	//}

	var pTpls []string
	pTpls = append(pTpls, "syntax = \"proto2\";")
	pTpls = append(pTpls, fmt.Sprintf("option go_package = \"%s\";", goPkgPath))
	pTpls = append(pTpls, fmt.Sprintf("package %s;", pkgPbDir))
	pTpls = append(pTpls, fmt.Sprintf("import \"%s\";", importDtoPkg))
	pTpls = append(pTpls, fmt.Sprintf("import \"%s\";", importCommonPkg))
	pTpls = append(pTpls, "")
	pTpls = append(pTpls, "")

	apiPbLinesMap := map[string][]string{}
	for _, pb := range pcode.basicAPIPbs {
		//println("path: ", pb.Path)
		//println("method: ", pb.Method)
		_, ok := apiPbLinesMap[pb.Path]
		if ok {
			continue
		}

		pTpls = append(pTpls, "// "+pb.api.genBasicAPIMethod())
		tplsLines := genAPIPbTpls(pb, packageMap)
		pTpls = append(pTpls, tplsLines...)

		apiPbLinesMap[pb.Path] = append(apiPbLinesMap[pb.Path], tplsLines...)

		//println(ToPrettyJSON(tplsLines))
		//println("")
		//println("")
	}

	pcode.apiPbLinesMap = apiPbLinesMap
	pcode.allPbLines = pTpls

	//apiDtoStr := strings.Join(pTpls, "\n")
	//err := ioutil.WriteFile(fmt.Sprintf("%s/%s_api.tpl.proto", tpl, module), []byte(apiDtoStr), 0644)
	//if err != nil {
	//	println(err.Error())
	//}

	types := []string{}
	for _, pb := range pcode.basicAPIPbs {
		for _, field := range pb.ReqFields {
			types = append(types, field.Type)
		}
	}

	uniqTypes := uniqSlice(types...)
	println(ToPrettyJSON(uniqTypes))
	pcode.innerStructTypes = uniqTypes
	inItemStrs, inItemTagsMap := parseInnerStruct(uniqTypes, pcode, packageMap)

	inStructTplDbs := genTplByJsonTagsMap(inItemTagsMap)
	inStructTagTypes := getStructTypeSet(inItemTagsMap)
	pcode.inItemTagsMap = inItemTagsMap

	println("all in item types:\n", ToPrettyJSON(inItemStrs))
	println("all in item types map:\n", ToPrettyJSON(inItemTagsMap))
	println(strings.Join(inStructTplDbs, "\n"))
	println("in struct tyeps:\n  ", ToPrettyJSON(inStructTagTypes))

	var innerTpls []string
	innerTpls = append(innerTpls, "syntax = \"proto2\";")
	innerTpls = append(innerTpls, fmt.Sprintf("option go_package = \"%s\";", goPkgPath))
	innerTpls = append(innerTpls, fmt.Sprintf("package %s;", pkgPbDir))
	innerTpls = append(innerTpls, "")
	innerTpls = append(innerTpls, "")
	innerTpls = append(innerTpls, "")

	innerTpls = append(innerTpls, inStructTplDbs...)

	pcode.innerStructsPbTpls = innerTpls

	//apiCommonStr := strings.Join(innerTpls, "\n")
	//err = ioutil.WriteFile(fmt.Sprintf("%s/%s_dto.tpl.proto", tpl, module), []byte(apiCommonStr), 0644)
	//if err != nil {
	//	println(err.Error())
	//}

	//
	println("out struct types:\n", ToPrettyJSON(pcode.outStructList))
	outItemStrs, ouItemTagsMap := parseOuterStruct(pcode.outStructList, pcode, packageMap)
	println("out struct types str:\n", ToPrettyJSON(outItemStrs))
	println("out struct types json tags:\n", ToPrettyJSON(ouItemTagsMap))
	ouStructTplDbsMaps := genOuterTplByJsonTagsMap(ouItemTagsMap)
	println("out struct types json tags:\n", ToPrettyJSON(ouItemTagsMap))
	//println(strings.Join(ouStructTplDbs, "\n"))

	outPkgPbLinesMap := map[string][]string{}
	for pName, items := range ouStructTplDbsMaps {
		var outerTpls []string
		outerTpls = append(outerTpls, "syntax = \"proto2\";")
		outerTpls = append(outerTpls, fmt.Sprintf("option go_package = \"git.garena.com/shopee/bg-logistics/tianlu/wmsv2-basic-v2-protobuf/apps/basic/pbbasicv2/%s\";", pkgPbDir))
		outerTpls = append(outerTpls, fmt.Sprintf("package %s;", pkgPbDir))
		outerTpls = append(outerTpls, "")
		outerTpls = append(outerTpls, "")
		outerTpls = append(outerTpls, "")
		outerTpls = append(outerTpls, items...)

		outPkgPbLinesMap[pName] = outerTpls

	}
	pcode.ouStructTplDbsMaps = outPkgPbLinesMap

	return nil
}

func genTplFile(base string, pcode *PCode) error {
	module := pcode.p.name
	pkgPbDir := "pb" + module
	tpl := base + "/" + pkgPbDir
	//tplCommon := base + "/pbcommon"
	tplCommon := tpl

	//dto
	apiDtoStr := strings.Join(pcode.allPbLines, "\n")
	err := ioutil.WriteFile(fmt.Sprintf("%s/%s_api.tpl.proto", tpl, module), []byte(apiDtoStr), 0644)
	if err != nil {
		println(err.Error())
	}

	//api
	apiCommonStr := strings.Join(pcode.innerStructsPbTpls, "\n")
	err = ioutil.WriteFile(fmt.Sprintf("%s/%s_dto.tpl.proto", tpl, module), []byte(apiCommonStr), 0644)
	if err != nil {
		println(err.Error())
	}

	//common
	for pName, items := range pcode.ouStructTplDbsMaps {
		commonStr := strings.Join(items, "\n")
		err = ioutil.WriteFile(fmt.Sprintf("%s/%s_entity.tpl.proto", tplCommon, pName), []byte(commonStr), 0644)
		if err != nil {
			println(err.Error())
		}
	}

	//tplFiles := []string{tplHead}
	//tplFiles = append(tplFiles, pcode.proxyAPIsDefs...)
	//err := ioutil.WriteFile(filePre+"_basic_api.go", []byte(strings.Join(tplFiles, "\n")), 0644)
	//if err != nil {
	//	return err
	//}
	//
	//dtoFiles := []string{tplHead}
	//dtoFiles = append(dtoFiles, pcode.proxySrcPkgAPIStructs...)
	//err = ioutil.WriteFile(filePre+"_basic_dto.go", []byte(strings.Join(dtoFiles, "\n")), 0644)
	//if err != nil {
	//	return err
	//}
	return nil
}

//request and resp
func genAPIPbTpls(pb *BASICAPI, packageMap map[string]*Package) []string {
	var lines []string
	lines = append(lines, fmt.Sprintf("message %sRequest{", pb.api.Method))
	for i, field := range pb.ReqFields {
		if field.Type == "context.Context" {
			continue
		}

		item := fmt.Sprintf("%s %s %s = %d;", toPbOption(field.Type), toPbType(field.Type, packageMap), ToSnakeCase(field.Alias), i)
		lines = append(lines, item)
	}
	lines = append(lines, "}")
	lines = append(lines, fmt.Sprintf("message %sResponse{", pb.api.Method))

	for i, field := range pb.RespTypeStr {
		if field == "*wmserror.WMSError" {
			continue
		}
		fieldType := field
		if strings.Contains(field, ".") {
			fieldType = strings.Split(field, ".")[1]
		}
		alias := fmt.Sprintf("Ret%d", i+1)
		item := fmt.Sprintf("%s %s %s = %d;", toPbOption(field), toPbType(fieldType, nil), ToSnakeCase(alias), i+1)
		lines = append(lines, item)
	}
	lines = append(lines, "}")

	return lines
}

func convertoBasicType(fType string, pkgMap map[string]*Package) string {
	if !strings.Contains(fType, ".") {
		return fType
	}
	if pkgMap == nil {
		return fType
	}

	actualType := strings.ReplaceAll(strings.ReplaceAll(fType, "[]", ""), "*", "")

	segs := strings.Split(actualType, ".")
	typePackage := strings.ReplaceAll(segs[0], "*", "")
	//只支持constant类型转换
	if typePackage != "constant" {
		return fType
	}

	for packagePath, p := range pkgMap {
		pathSegs := strings.Split(packagePath, "/")
		if pathSegs[len(pathSegs)-1] == typePackage {
			ktype, err := p.FindType(segs[1])
			if err == nil {
				ctType := ktype.def.String()
				println(fmt.Sprintf("keyType:%s convert to %s", fType, ctType))
				return ctType
			}
		}
	}

	return fType

}
func toPbType(fType string, packageMap map[string]*Package) string {
	fieldType := convertoBasicType(fType, packageMap)

	if fieldType == "string" {
		return "string"
	}
	if fieldType == "[]string" {
		return "string"
	}
	if fieldType == "[]int64" {
		return "int64"
	} else if fieldType == "int64" {
		return "int64"
	} else if strings.Contains(fieldType, "[]") {
		return toPbSliceStructItemType(fieldType)
	}
	switch fieldType {
	case "string":
		return "string"
	case "int64":
		return "int64"
	case "map[string]interface{}":
		return "MapItem"
	default:
		ftype := strings.ReplaceAll(fieldType, "*", "")
		if strings.Contains(ftype, ".") {
			return strings.Split(ftype, ".")[1] + "Item"
		}
		return ftype + "Item"
	}
}

func toPbSliceStructItemType(fieldType string) string {
	actualType := strings.ReplaceAll(strings.ReplaceAll(fieldType, "[]", ""), "*", "")
	split := strings.Split(actualType, ".")
	pType := actualType
	if len(split) > 1 {
		pType = split[1]
	}
	return pType + "Item"
}

func assignToPbType(field *ReqField) string {
	pbType := field.Type

	fieldType := pbType
	if fieldType == "string" {
		return fmt.Sprintf("convert.String(%s)", field.Alias)
	}
	if fieldType == "[]string" {
		return field.Alias
	}
	if fieldType == "[]int64" {
		return field.Alias
	} else if fieldType == "int64" {
		return fmt.Sprintf("convert.Int64(%s)", field.Alias)

	} else if fieldType == "MapItem" {
		return "mapItemLists"
	} else if fieldType == "map[string]interface{}" {
		return "mapItemLists"
	} else if isSturctItems(fieldType) {
		return fmt.Sprintf("%sItems", field.Alias)
	}

	return fmt.Sprintf("%sItem", field.Alias)
}

func convertToPbType(fieldType, val string) string {

	if fieldType == "string" {
		return fmt.Sprintf("convert.String(%s)", val)
	}
	if fieldType == "[]string" {
		return val
	}
	if fieldType == "[]int64" {
		return val
	} else if fieldType == "int64" {
		return fmt.Sprintf("convert.Int64(%s)", val)

	} else if fieldType == "MapItem" {
		return "mapItemLists"
	} else if fieldType == "map[string]interface{}" {
		return "mapItemLists"
	} else if isSturctItems(fieldType) {
		return fmt.Sprintf("%sItems", val)
	}

	return fmt.Sprintf("%sItem", val)
}

func (field *ReqField) assignToPbType() string {
	pbType := field.Type

	fieldType := pbType
	if fieldType == "string" {
		return fmt.Sprintf("convert.String(%s)", field.Alias)
	}
	if fieldType == "[]string" {
		return field.Alias
	}
	if fieldType == "[]int64" {
		return field.Alias
	} else if fieldType == "int64" {
		return fmt.Sprintf("convert.Int64(%s)", field.Alias)

	} else if fieldType == "MapItem" {
		return "mapItemLists"
	} else if fieldType == "map[string]interface{}" {
		return "mapItemLists"
	} else if isSturctItems(fieldType) {
		return fmt.Sprintf("%sItems", field.Alias)
	}

	return fmt.Sprintf("%sItem", field.Alias)
}

func isSturctItems(fieldType string) bool {
	isBasicType := strings.Contains(fieldType, "int64") || strings.Contains(fieldType, "string")
	return strings.Contains(fieldType, "[]") &&
		!isBasicType
}

func parseInnerStruct(uniqTypes []string, pcode *PCode, packageMap map[string]*Package) ([]string, map[string][]*JsonTag) {
	var itemTypes []ItemType
	for _, uniqType := range uniqTypes {
		itemTypes = append(itemTypes, ItemType(uniqType))
	}
	inItemStrs := []string{}
	inItemTagsMap := map[string][]*JsonTag{}
	for _, itemType := range itemTypes {
		if itemType.IsInnerStruct() {
			inItemStrs = append(inItemStrs, string(itemType))
			for _, file := range pcode.p.files {
				itemTypeStr := strings.ReplaceAll(string(itemType), "*", "")
				itemTypeStr = strings.ReplaceAll(string(itemTypeStr), "[]", "")
				t, err := file.FindType(itemTypeStr)
				if err != nil && strings.Contains(err.Error(), "is not found") {
					//println(itemType, "is not found")
					continue
				}
				//for _, field := range t.def.(*StructType).Fields() {
				//	println(field.Definition().String())
				//}
				for _, field := range t.def.(*StructType).fields {
					inItemTagsMap[itemTypeStr] = append(inItemTagsMap[itemTypeStr], NewJsonTag(field, packageMap))

				}
				originDef := t.Definition().String()
				withoutHeadDef := strings.ReplaceAll(originDef, "struct {", fmt.Sprintf("struct %s{", itemTypeStr))
				//def = append(def, withoutHeadDef)
				println(withoutHeadDef)
				//println(t)
			}
		}
	}
	return inItemStrs, inItemTagsMap
}

func parseOuterStruct(uniqTypes []string, pcode *PCode, packageMap map[string]*Package) ([]string, map[string][]*JsonTag) {
	var itemTypes []ItemType
	for _, uniqType := range uniqTypes {
		itemTypes = append(itemTypes, ItemType(uniqType))
	}
	inItemStrs := []string{}
	outItemTagsMap := map[string][]*JsonTag{}
	for _, itemType := range itemTypes {
		if itemType.IsOuterStruct() {
			actualType := strings.ReplaceAll(strings.ReplaceAll(itemType.String(), "[]", ""), "*", "")

			segs := strings.Split(actualType, ".")
			typePackage := strings.ReplaceAll(segs[0], "*", "")
			for packagePath, p := range packageMap {
				pathSegs := strings.Split(packagePath, "/")
				if pathSegs[len(pathSegs)-1] == typePackage {
					ktype, err := p.FindType(segs[1])
					if err != nil && strings.Contains(err.Error(), "is not found") {
						//println(itemType, "is not found")
						continue
					}

					if structType, ok := ktype.def.(*StructType); ok {
						inItemStrs = append(inItemStrs, actualType)
						if _, exist := outItemTagsMap[actualType]; exist {
							continue
						}
						for _, field := range structType.fields {
							outItemTagsMap[actualType] = append(outItemTagsMap[actualType], NewJsonTag(field, packageMap))
						}
					} else {
						println("out struct is not a struct type; %s", itemType)
					}
				}
			}
			for _, file := range pcode.p.files {
				itemTypeStr := strings.ReplaceAll(string(itemType), "*", "")
				t, err := file.FindType(itemTypeStr)
				if err != nil && strings.Contains(err.Error(), "is not found") {
					//println(itemType, "is not found")
					continue
				}
				//for _, field := range t.def.(*StructType).Fields() {
				//	println(field.Definition().String())
				//}
				for _, field := range t.def.(*StructType).fields {
					outItemTagsMap[itemTypeStr] = append(outItemTagsMap[itemTypeStr], NewJsonTag(field, packageMap))

				}
				originDef := t.Definition().String()
				withoutHeadDef := strings.ReplaceAll(originDef, "struct {", fmt.Sprintf("struct %s{", itemTypeStr))
				//def = append(def, withoutHeadDef)
				println(withoutHeadDef)
				//println(t)
			}
		}
	}
	return inItemStrs, outItemTagsMap
}

func getStructTypeSet(tagsMap map[string][]*JsonTag) []string {
	var items []string
	for _, tags := range tagsMap {
		for _, tag := range tags {
			items = append(items, tag.KeyType)
		}
	}
	return uniqSlice(items...)
}

func genTplByJsonTagsMap(tagsMap map[string][]*JsonTag) []string {

	var items []string
	for objName, tags := range tagsMap {
		item := []string{}
		tplHead := fmt.Sprintf("message  %sItem{", objName)
		var pbFields = []string{}
		for i, tag := range tags {
			fieldStr := tag.ToPbFieldDef(i)
			pbFields = append(pbFields, fieldStr)
		}
		tplFoot := fmt.Sprintf("}")

		item = append(item, tplHead)
		item = append(item, pbFields...)
		item = append(item, tplFoot)
		items = append(items, strings.Join(item, "\n"))
	}
	return items
}

func genOuterTplByJsonTagsMap(tagsMap map[string][]*JsonTag) map[string][]string {

	var retItemMaps = map[string][]string{}
	for objName, tags := range tagsMap {
		segs := strings.Split(objName, ".")
		packageName := segs[0]
		vType := segs[1]
		var item []string
		tplHead := fmt.Sprintf("message  %sItem{", vType)
		var pbFields = []string{}
		for i, tag := range tags {
			fieldStr := tag.ToPbFieldDef(i)
			pbFields = append(pbFields, fieldStr)
		}
		tplFoot := fmt.Sprintf("}")

		item = append(item, tplHead)
		item = append(item, pbFields...)
		item = append(item, tplFoot)
		retItemMaps[packageName] = append(retItemMaps[packageName], item...)
	}
	return retItemMaps
}

type JsonTag struct {
	Key     string
	KeyType string
	JsonTag string
	isValid bool
}

func (t JsonTag) ToPbFieldDef(keyIdex int) string {
	return fmt.Sprintf("%s %s %s = %d;", t.ToPbOption(), t.toPbType(), t.Key, keyIdex+1)
}

func (t JsonTag) ToPbOption() string {
	return toPbOption(t.KeyType)
}

func toPbOption(t string) string {
	if strings.Contains(t, "[") {
		return "repeated"
	}
	return "optional"
}

func (t JsonTag) toPbType() string {
	fieldType := strings.ReplaceAll(t.KeyType, "*", "")
	fieldType = strings.ReplaceAll(fieldType, "[]", "")

	switch fieldType {
	case "string":
		return "string"
	case "int64":
		return "int64"
	default:
		return fieldType
	}
}

//tag: like json:"whs_id,omitempty"
func NewJsonTag(field *Field, packageMap map[string]*Package) *JsonTag {
	tag := field.Tags()
	keyType := field.def.String()
	key := strings.Split(tag.Get("json"), ",")[0]
	//segs := strings.Split(tag, ":")
	//isValid := true
	//if len(segs) != 2 || segs[0] != "json" {
	//	isValid = false
	//}
	//tagVal := segs[1]
	//tagValWithoutEmpty := strings.ReplaceAll(tagVal, "\"", "")
	//
	//key := strings.Split(tagValWithoutEmpty, ",")[0]

	//如： "*constant.SkuSizeType", 转换成int64\或者string
	if !strings.Contains(keyType, "[") && strings.Contains(keyType, ".") {
		segs := strings.Split(keyType, ".")
		typePackage := strings.ReplaceAll(segs[0], "*", "")
		for packagePath, p := range packageMap {
			pathSegs := strings.Split(packagePath, "/")
			if pathSegs[len(pathSegs)-1] == typePackage {
				ktype, err := p.FindType(segs[1])
				if err == nil {
					ctType := ktype.def.String()
					println(fmt.Sprintf("keyType:%s convert to %s", keyType, ctType))
					keyType = ctType
				}
			}
		}
	}

	isValid := len(key) > 0

	return &JsonTag{
		Key:     key,
		KeyType: keyType,
		isValid: isValid,
	}
}

func uniqSlice(types ...string) []string {
	set := hashset.New()
	for _, s := range types {
		set.Add(s)
	}

	var ret []string
	for _, i := range set.Values() {
		ret = append(ret, i.(string))
	}
	return ret
}

func genSrcProxyCodeFile(conf *CodeGenConf, pcode *PCode) error {
	module := pcode.p.name
	filePre := conf.srcBase + "/" + module

	packageHead := fmt.Sprintf("package %s", module)
	apiFiles := []string{packageHead}
	apiFiles = append(apiFiles, pcode.srcPkgProxyFuncs...)
	err := ioutil.WriteFile(filePre+"_proxy_handler.go", []byte(strings.Join(apiFiles, "\n")), 0644)
	if err != nil {
		return err
	}

	//proxy main.go
	proxyMain := []string{packageHead}

	val := "const module = \"%s\"\n\nvar apiIdempotent = wmsbasicproxy.APIIdempotent()\n\nfunc getBasicHandler() wmsbasicproxy.BasicProxyHandler {\n\treturn wmsbasicproxy.GetModuleHandler(module)\n}\n"
	proxyMain = append(proxyMain, fmt.Sprintf(val, module))
	//
	//type HighValueManagerProxy struct {
	//	highValueManager         HighValueManager
	//	highValueManagerProxyAPI wmsbasic.MhighvalueAPI
	//}
	proxyMain = append(proxyMain, fmt.Sprintf("type %sProxy struct{", conf.proxyStructType))
	proxyMain = append(proxyMain, fmt.Sprintf("\t %s %s", lowerFirstChar(conf.proxyStructType), conf.proxyStructType))
	proxyMain = append(proxyMain, fmt.Sprintf("\t %sProxyAPI wmsbasic.%sAPI", lowerFirstChar(conf.proxyStructType), upFirstChar(module)))
	proxyMain = append(proxyMain, "}")

	err = ioutil.WriteFile(filePre+"_proxy_main.go", []byte(strings.Join(proxyMain, "\n")), 0644)
	if err != nil {
		return err
	}
	return nil
}

type SrcEndPoint string

func NewSrcEndPoint(p, f string) SrcEndPoint {
	return SrcEndPoint(fmt.Sprintf("%s#%s", p, f))
}

type PCode struct {
	p *Package
	//代理包定义
	srcPkgProxyFuncs []string
	//源包代理方法体
	srcPkgProxyFuncMap map[SrcEndPoint]string

	outStructList []string
	//代理的包纬度接口定义
	proxyAPIsDefs []string
	//代理的包纬度接口struct
	proxySrcPkgAPIStructs []string

	//所有的API
	basicAPIPbs []*BASICAPI

	basicAPIDefMap  map[SrcEndPoint]string
	basicAPIReqsMap map[SrcEndPoint]string
	basicAPIPbsMap  map[SrcEndPoint]*BASICAPI

	//API 对应的pb定义
	allPbLines         []string
	apiPbLinesMap      map[string][]string
	innerStructTypes   []string
	inItemTagsMap      map[string][]*JsonTag
	innerStructsPbTpls []string

	//outer struct
	ouStructTplDbsMaps map[string][]string
}

func (pcode PCode) genProxyAPIStructDefAndConstruct() string {
	pkgName := pcode.p.name
	actualApiName := fmt.Sprintf("%sBasicAPI", upFirstChar(pkgName))
	apiName := fmt.Sprintf("%sAPI", upFirstChar(pkgName))
	objSign := fmt.Sprintf(" type %s struct{", actualApiName)
	objSign += "\n\t Client Client"
	objSign += "\n\t }"
	//func NewMsizetypeBasicAPI() *MsizetypeBasicAPI {
	//	return &MsizetypeBasicAPI{}
	//}

	objConsturcts := []string{}
	newStr := fmt.Sprintf("func New%s() %s {", apiName, apiName)
	returnStr := fmt.Sprintf("return &%s{", actualApiName)
	returnStr += "\n\tClient: NewClient(),"
	returnStr += "\n\t}"

	objConsturcts = append(objConsturcts, newStr)
	objConsturcts = append(objConsturcts, returnStr)
	objConsturcts = append(objConsturcts, "}")

	return objSign + "\n" + strings.Join(objConsturcts, "\n")

}

func parsePCode(p *Package) *PCode {
	code := &PCode{
		p: p,
	}
	inStructSet := hashset.New()
	outStructSet := hashset.New()
	apis := parseFuncs(p, inStructSet, outStructSet)

	var funcDefs []string
	var basicAPIs []string
	var basicAPIReqs []string
	var basicAPIPbs []*BASICAPI

	var apiFuncDefsMap = map[SrcEndPoint]string{}
	var basicAPIsMap = map[SrcEndPoint]string{}
	var basicAPIReqsMap = map[SrcEndPoint]string{}
	var basicAPIPbsMap = map[SrcEndPoint]*BASICAPI{}
	for _, api := range apis {
		if !isExported(api.Method) {
			//println("method is not exported: ", api.Method)
			continue
		}
		endpoint := NewSrcEndPoint(api.Pkg.name, api.Method)
		funcDefs = append(funcDefs, api.proxyFuncBody2())
		apiFuncDefsMap[endpoint] = api.proxyFuncBody2()

		basicAPIs = append(basicAPIs, api.BasicAPIInterfaceSignWithComment())
		basicAPIsMap[endpoint] = api.BasicAPIInterfaceSignWithComment()

		basicAPIReqs = append(basicAPIReqs, api.proxyPbAPIReq())
		basicAPIReqsMap[endpoint] = api.proxyPbAPIReq()

		basicAPIPbs = append(basicAPIPbs, api.proxyPbAPI())
		basicAPIPbsMap[endpoint] = api.proxyPbAPI()
	}

	code.srcPkgProxyFuncMap = apiFuncDefsMap
	code.basicAPIDefMap = basicAPIsMap

	code.basicAPIReqsMap = basicAPIReqsMap
	code.basicAPIPbsMap = basicAPIPbsMap

	//prttryStr("func body", strings.Join(funcDefs, "\n"))
	code.proxyAPIsDefs = buildPackageProxyBasicAPI(p, uniqSlice(basicAPIs...))
	code.basicAPIPbs = basicAPIPbs
	//源包
	code.srcPkgProxyFuncs = funcDefs
	//代理包
	code.proxySrcPkgAPIStructs = pReqItemStrs(apis)

	//prttryStr("basic api ", strings.Join(basicAPIs, "\n\n"))
	//prttryStr("basic api req", strings.Join(basicAPIReqs, "\n\n"))
	var outStructTypeList []string
	for _, i := range inStructSet.Values() {
		println(p.name, " inner struct", i.(string))
	}
	for _, i := range outStructSet.Values() {
		//println(p.name, " out struct", i.(string))
		outStructTypeList = append(outStructTypeList, i.(string))
	}
	code.outStructList = outStructTypeList

	return code

}

func pReqItemStrs(apis []*API) []string {
	reqDefSet := hashset.New()
	for _, api := range apis {
		if !isExported(api.Method) {
			continue
		}
		for _, itemStr := range api.proxyProxyAPIReqItem() {
			reqDefSet.Add(itemStr)
		}
	}
	reqItems := []string{}
	for _, i := range reqDefSet.Values() {
		reqItems = append(reqItems, i.(string))
	}
	return reqItems
}

func buildPackageProxyBasicAPI(p *Package, basicAPIs []string) []string {
	var wmsbasicAPI []string
	wmsbasicAPI = append(wmsbasicAPI, fmt.Sprintf("type %sAPI interface {", upFirstChar(p.name)))
	wmsbasicAPI = append(wmsbasicAPI, basicAPIs...)
	wmsbasicAPI = append(wmsbasicAPI, "}")
	return wmsbasicAPI
}

func parseFuncs(p *Package, inStructSet *hashset.Set, outStructSet *hashset.Set) []*API {
	var apis []*API
	for _, function := range p.Functions() {
		receiver := function.receiver
		//todo filter proxy_main 方法

		if receiver == nil {
			println(function.name, " is not receiver")
			continue
		}
		if strings.Contains(strings.ToLower(function.file.fileName), "proxy") {
			continue
		}
		//like skuManager
		originObjName := receiver.def.String()
		receiverName := originObjName + "Proxy"
		receiverAlias := receiver.name
		funcWithReciver := fmt.Sprintf("func (%v %s) ", receiverAlias, receiverName) + function.name
		getDefinitionWithName := function.def.getDefinitionWithName(funcWithReciver)
		//println("getDefinitionWithName:=", getDefinitionWithName)

		api := genReqAndResp(function)
		api.FuncSignStr = getDefinitionWithName
		api.ReceiverAlias = receiverAlias
		api.ReceiverName = strings.ReplaceAll(originObjName, "*", "")
		api.Pkg = p
		apis = append(apis, api)

		//println(ToPrettyJSON(api))

		for _, i := range api.genInnerDefPkgStructs() {
			inStructSet.Add(i)
		}
		for _, i := range api.genOuterDefPkgStructs() {
			outStructSet.Add(i)
		}
	}
	return apis
}

func prttryStr(label string, body string) {
	println()
	println(color.InGreen(fmt.Sprintf("====================== [%s] start =====================", label)))
	println(body)
	println(color.InGreen(fmt.Sprintf("====================== [%s] end =====================", label)))
	println()

}

type API struct {
	Path    string
	Package string
	// SearchAllTaskSizeType
	Method        string
	Req           map[string]string
	ReqFields     []*ReqField
	Resp          []string
	Func          *FuncType
	FuncSignStr   string
	ReceiverAlias string
	ReceiverName  string
	Pkg           *Package
	genBasicV2Err bool
}

type BASICAPI struct {
	Path        string
	Package     string
	Method      string
	Req         map[string]string
	ReqFields   []*ReqField
	RespTypeStr []string
	Pkg         *Package
	api         API
}

func (b BASICAPI) ProxyOpenapiMethod() string {
	routerMethod := "RegisterGetOpenApiURL"
	if b.Method == "POST" {
		routerMethod = "RegisterPostOpenApiURL"
	}
	return routerMethod

}

func (b BASICAPI) invokeAlias() []string {
	var items []string
	for _, field := range b.ReqFields {
		if field.isContext() {
			items = append(items, field.Alias)
		} else {
			items = append(items, field.aliasDef())

		}
	}
	return items
}

func (b BASICAPI) viewInvokeAlias() []string {
	var items []string
	for _, field := range b.ReqFields {
		items = append(items, field.formatFieldAlias())
	}
	return items
}

func (b BASICAPI) viewHandlerErr() string {
	return b.api.viewHandlerErr()
}

func (b API) viewHandlerErr() string {
	var lines []string
	lines = append(lines, "if err!=nil {")
	lines = append(lines, "return nil, err.Mark()")
	lines = append(lines, "}")
	return strings.Join(lines, "\n")
}

type ReqField struct {
	Alias string
	Type  string
}

func (f ReqField) defNormalTypeSign() string {
	return fmt.Sprintf("var %s %s", f.aliasDef(), f.Type)
}
func (f ReqField) defTypeSign() string {
	return fmt.Sprintf("var %s %s", f.aliasDef(), f.Type)
}

func (f ReqField) defSturctType() string {
	return fmt.Sprintf("var %s %s", f.aliasDef(), f.Type)
}

func (f ReqField) defSturctSliceType() string {
	return fmt.Sprintf("var %s %s", f.aliasDef(), f.Type)
}

func (f ReqField) aliasDef() string {
	if isNormalType(f.Type) {
		return f.Alias
	} else {
		if isSturctItems(f.Type) {
			return f.Alias + "Items"
		} else {
			return f.Alias + "Item"
		}
	}
}

func (f ReqField) isContext() bool {
	return f.Type == "context.Context"

}

func (f ReqField) isPageInItem() bool {
	return f.Type == "*paginator.PageIn"
}

func (f ReqField) isUpdateMap() bool {
	return f.Type == "map[string]interface{}"
}

func (f ReqField) convertPageInAssignLines(module string) []string {
	field := &f
	var lines []string
	pbType := assignToPbType(field)
	lines = append(lines, fmt.Sprintf("%s:=&pb%s.%s{", pbType, module, toPbSliceStructItemType(field.Type)))
	//		Pageno:     convert.Int64(pageIn.Pageno),
	//		Count:      convert.Int64(pageIn.Count),
	//		OrderBy:    convert.String(pageIn.OrderBy),
	//		IsGetTotal: convert.Bool(pageIn.IsGetTotal),
	alias := field.Alias
	lines = append(lines, fmt.Sprintf("\tPageno:     convert.Int64(%s.Pageno),", alias))
	lines = append(lines, fmt.Sprintf("\tCount:     convert.Int64(%s.Count),", alias))
	lines = append(lines, fmt.Sprintf("\tOrderBy:     convert.String(%s.OrderBy),", alias))
	lines = append(lines, fmt.Sprintf("\tIsGetTotal:     convert.Bool(%s.IsGetTotal),", alias))
	lines = append(lines, "}")
	return lines
}

func (f ReqField) convertPbToBasic(module string) []string {
	field := &f
	var lines []string
	line := `
	var %s *paginator.PageIn
	if pageInItem := req.PageIn; pageInItem != nil {
		%s = &paginator.PageIn{
			Pageno:     pageInItem.GetPageno(),
			Count:      pageInItem.GetCount(),
			OrderBy:    pageInItem.GetOrderBy(),
			IsGetTotal: pageInItem.GetIsGetTotal(),
		}
	}
`
	lines = append(lines, fmt.Sprintf(line, field.Alias, field.Alias))
	return lines
}

func (f ReqField) toDefItemOrItems(module string) []string {
	field := &f
	var params = []string{}
	pbType := assignToPbType(field)
	if isSturctItems(field.Type) {
		params = append(params, fmt.Sprintf("%s:=[]*pb%s.%s{}", pbType, module, toPbSliceStructItemType(field.Type)))
	} else {
		params = append(params, fmt.Sprintf("%s:=&pb%s.%s{}", pbType, module, toPbSliceStructItemType(field.Type)))
	}
	return params

}
func (f ReqField) toDefBasicItemOrItems(module string) []string {
	field := &f
	var params = []string{}
	if strings.Contains(field.Type, ".") {
		if strings.Contains(field.Type, "[]") {
			return []string{fmt.Sprintf("%s=%s{}", field.formatFieldAlias(), field.Type)}
		} else {
			type1 := strings.ReplaceAll(field.Type, "*", "")
			return []string{fmt.Sprintf("%s=&%s{}", field.formatFieldAlias(), type1)}
		}
	}

	//eg 请求参数为:[]*msizetype.conditions
	type1 := strings.ReplaceAll(strings.ReplaceAll(field.Type, "*", ""), "[]", "")
	if isSturctItems(field.Type) {
		params = append(params, fmt.Sprintf("%s=[]*%s.%s{}", field.formatFieldAlias(), module, type1))
	} else {
		params = append(params, fmt.Sprintf("%s=&%s.%s{}", field.formatFieldAlias(), module, type1))
	}
	return params

}

func (f ReqField) toDefBasicItemOrItemsWithoutInit(module string) []string {
	field := &f
	var params = []string{}
	if strings.Contains(field.Type, ".") {
		if strings.Contains(field.Type, "[]") {
			return []string{fmt.Sprintf("var %s %s", field.Alias, field.Type)}
		} else {
			type1 := strings.ReplaceAll(field.Type, "*", "")
			return []string{fmt.Sprintf("var %s *%s", f.formatFieldAlias(), type1)}
		}
	}

	type1 := strings.ReplaceAll(strings.ReplaceAll(field.Type, "*", ""), "[]", "")
	if isSturctItems(field.Type) {
		params = append(params, fmt.Sprintf("var %s []*%s.%s", field.Alias, module, type1))
	} else {
		params = append(params, fmt.Sprintf("var %s *%s.%s", field.Alias, module, type1))
	}
	return params

}

func (f ReqField) formatFieldAlias() string {
	field := &f
	if field.Alias == "entity" {
		return "entityItem"
	}
	return field.Alias
}

func (f ReqField) genDealCopyJsErrLines(isDefineJsErr *bool, api API) []string {
	field := &f
	copyLine := "jsErr := copier.Copy(%s,%s)"
	var params []string
	pbType := assignToPbType(field)
	if *isDefineJsErr {
		copyLine = strings.ReplaceAll(copyLine, ":", "")
	} else {
		a := true
		isDefineJsErr = &a
	}
	params = append(params, fmt.Sprintf(copyLine, field.Alias, pbType))

	retItemVars := api.apiRets()
	errLines := dealCopyErrLines(retItemVars)
	params = append(params, errLines...)
	params = append(params, "}")
	return params
}

func (field *ReqField) toPbType() interface{} {
	return toPbType(field.Type, nil)
}

func (api *API) proxyFuncBody() string {
	var bodyStr []string
	bodyStr = append(bodyStr, api.FuncSignStr+"{")

	//var ret1 []*entity.CellSizeType
	//var ret2 int64
	//var ret3 *wmserror.WMSError
	for i, ret := range api.Resp {
		v := fmt.Sprintf("var %s %s", fmt.Sprintf("ret%d", i+1), ret)
		bodyStr = append(bodyStr, v)
	}

	//
	//originHandler := func(ctx context.Context) {
	//	ret1, ret2, ret3 = c.origin.SearchCellSizeList(ctx, whsID)
	//}
	retParams := []string{}
	for i := range api.Resp {
		retParams = append(retParams, fmt.Sprintf("ret%d ", i+1))
	}
	rets := strings.Join(retParams, ", ")

	bodyStr = append(bodyStr, "\toriginHandler := func(ctx context.Context) {")
	params := []string{}
	for _, field := range api.ReqFields {
		params = append(params, field.Alias)
	}
	paramsStr := strings.Join(params, ", ")

	callOriginal := fmt.Sprintf("= %s.%s.%s(%s)", api.ReceiverAlias, lowerFirstChar(api.ReceiverName), api.Method, paramsStr)
	bodyStr = append(bodyStr, rets+callOriginal)
	bodyStr = append(bodyStr, "\t}")

	//proxyHandler := func(ctx context.Context) *wmserror.WMSError {
	//	req := &pbmsizetype.SearchCellSizeListReq{
	//		WhsID: whsID,
	//	}

	bodyStr = append(bodyStr, "proxyHandler := func(ctx context.Context) *wmserror.WMSError {")
	bodyStr = append(bodyStr, fmt.Sprintf("req := &pb%s.%sReq{", api.Package, api.Method))
	var reqFieldsStr []string
	for _, field := range api.ReqFields {
		fieldParam := field.Alias
		fieldType := upFirstChar(fieldParam)
		reqFieldsStr = append(reqFieldsStr, fmt.Sprintf("\t%s:%s,", fieldType, fieldParam))
	}
	bodyStr = append(bodyStr, reqFieldsStr...)
	bodyStr = append(bodyStr, "}")

	//	apiResp, err := c.basicAPI.SearchCellSizeList(ctx, req)
	//	if err != nil {
	//		return err.Mark()
	//	}
	var callProxy string
	if len(api.Resp) > 1 {
		callProxy = fmt.Sprintf("apiResp, err := %s.basicAPI.%s(ctx, req)", api.ReceiverAlias, api.Method)
	} else {
		callProxy = fmt.Sprintf("err := %s.basicAPI.%s(ctx, req)", api.ReceiverAlias, api.Method)
	}
	bodyStr = append(bodyStr, callProxy)
	bodyStr = append(bodyStr, "\tif err != nil {")
	bodyStr = append(bodyStr, "\treturn err.Mark()")
	bodyStr = append(bodyStr, "\t}")

	//	ret1, ret2, ret3 = apiResp.GetRet1(), apiResp.GetRet2(), apiResp.GetRet3()
	//	return nil
	//}
	proxyRets := []string{}
	proxyRetParams := []string{}
	for i := range api.Resp {
		if i == len(api.Resp)-1 {
			continue
		}
		proxyRets = append(proxyRets, fmt.Sprintf("apiResp.GetRet%d()", i))
		proxyRetParams = append(proxyRetParams, fmt.Sprintf("ret%d", i))
	}
	if len(proxyRetParams) > 0 {
		bodyStr = append(bodyStr, fmt.Sprintf("%s = %s", strings.Join(proxyRetParams, ", "), strings.Join(proxyRets, ", ")))
	}
	bodyStr = append(bodyStr, "return nil")
	bodyStr = append(bodyStr, "}")

	//
	//endPoint := "SearchCellSizeList"
	//doBasicHandler(ctx, endPoint, originHandler, proxyHandler)
	//return ret1, ret2, ret3

	bodyStr = append(bodyStr, fmt.Sprintf("endPoint := \"%s\"", api.Method))
	if api.genBasicAPIMethod() == "GET" {
		bodyStr = append(bodyStr, "getBasicHandler()(ctx, endPoint, originHandler, proxyHandler, apiIdempotent)")
	} else {
		bodyStr = append(bodyStr, "getBasicHandler()(ctx, endPoint, originHandler, proxyHandler)")
	}
	bodyStr = append(bodyStr, "return "+rets)
	bodyStr = append(bodyStr, "}")

	return strings.Join(bodyStr, "\n")
}
func (api *API) proxyBasicFuncBody(pbPkg *Package, packageMap map[string]*Package) string {

	//module := api.Pkg.name
	var bodyStr []string

	//var ret1 []*entity.CellSizeType
	//var ret2 int64
	//var err *wmserror.WMSError

	retItems := api.apiRetDefs()

	bodyStr = append(bodyStr, retItems...)
	bodyStr = append(bodyStr, "")

	var params []string
	isDefineJsErr, preDefLines := api.genWmsV2ToBasicPreItemDefLines(packageMap)
	params = append(params, preDefLines...)

	params = append(params, "\n// do requets")
	params = append(params, fmt.Sprintf("req:=&%s{", api.apiPbReqType()))
	for _, field := range api.ReqFields {
		if field.Type == "context.Context" {
			continue
		}
		pbType := api.parsePbFieldType(pbPkg, field)

		//item := fmt.Sprintf("\t%s:%s,", pbType, assignToPbType(field))
		var item string
		if api.Method == "SearchHighValueByHvIds" && field.Alias == "isGlobal" {
			item = fmt.Sprintf("\t%s:%s,", pbType, "convert.Int64(isGlobal)")
		} else {
			item = fmt.Sprintf("\t%s:%s,", pbType, field.assignToPbType())
		}

		params = append(params, item)
	}
	params = append(params, "}")

	var resps []string
	resps = append(resps, fmt.Sprintf("resp:=&%s{}", api.apiPbRespType()))

	bodyStr = append(bodyStr, params...)
	bodyStr = append(bodyStr, resps...)

	method := api.genBasicAPIMethod()
	method = upFirstChar(strings.ToLower(method))
	bodyStr = append(bodyStr, fmt.Sprintf("\t_, err = m.Client.%s(ctx, %s, req, resp, DefaultTimeOut)", method, api.endpointEnum()))

	bodyStr = append(bodyStr, "\tif err != nil {")
	//	if err != nil {
	//		return err.Mark()
	//	}
	lines := api.genNormalErrLines()
	bodyStr = append(bodyStr, lines...)

	copyLine := "jsErr := copier.Copy(%s,%s)"

	retLines := api.assignReturnAssign(isDefineJsErr, copyLine)
	bodyStr = append(bodyStr, retLines...)

	returnVal := "\t\treturn   nil"
	if len(api.apiRets()) > 1 {
		errMsg := "\t\treturn  %s, nil"
		returnVal = fmt.Sprintf(errMsg, strings.Join(api.apiRets()[0:len(api.apiRets())-1], ","))
	}

	bodyStr = append(bodyStr, returnVal)

	bodyStr = append(bodyStr, "\t}")
	bodyStr = append(bodyStr, "\n")

	return strings.Join(bodyStr, "\n")
}

func (api *API) assignReturnAssign(isDefineJsErr bool, copyLine string) []string {
	var bodyStr []string
	var respAssgins []string
	if len(api.apiRets()) > 0 {
		for i, ret := range api.Resp {
			if ret == "*wmserror.WMSError" {
				continue
			}
			retIdex := i + 1
			curRet := fmt.Sprintf("ret%d", retIdex)
			respRet := fmt.Sprintf("resp.GetRet%d()", retIdex)
			rawRespRet := fmt.Sprintf("resp.Ret%d", retIdex)
			if isNormalType(ret) {
				assign := fmt.Sprintf("%s = %s", curRet, respRet)
				respAssgins = append(respAssgins, assign)
			} else {
				if isDefineJsErr {
					copyLine = strings.ReplaceAll(copyLine, ":", "")
				} else {
					isDefineJsErr = true
				}

				respAssgins = append(respAssgins, fmt.Sprintf("if %s !=nil{", rawRespRet))
				respAssgins = append(respAssgins, fmt.Sprintf(copyLine, respRet, "&"+curRet))
				errLines := dealCopyErrLines(api.apiRets())

				respAssgins = append(respAssgins, errLines...)
				respAssgins = append(respAssgins, "}")
				respAssgins = append(respAssgins, "}")
			}
		}
	}
	bodyStr = append(bodyStr, "")
	if len(api.apiRets()) > 1 {
		bodyStr = append(bodyStr, "// 转换返回值")
	}

	bodyStr = append(bodyStr, respAssgins...)
	return bodyStr
}

func (api *API) genNormalErrLines() []string {
	bodyStr := []string{}
	if len(api.apiRets()) > 1 {
		errMsg := "\t\treturn  %s, err.Mark()"
		bodyStr = append(bodyStr, fmt.Sprintf(errMsg, strings.Join(api.apiRets()[0:len(api.apiRets())-1], ",")))
	} else {
		bodyStr = append(bodyStr, "return err.Mark()")
	}
	bodyStr = append(bodyStr, "\t}")
	return bodyStr
}

//如：whsId对应pb可能是：WhsID
func (api *API) parsePbFieldType(pbPkg *Package, field *ReqField) string {
	fieldType := strings.ToLower(field.Alias)
	pbType := upFirstChar(field.Alias)
	if api.parsePbReqType(pbPkg)[fieldType] != nil {
		pbType = api.parsePbReqType(pbPkg)[fieldType].name
	}

	if pbType == "Size" && api.apiPbReqType() == "pbmsizetype.CreateSkuWeightTypeRequest" {
		pbType = "Item"
	}
	return pbType
}

func (api *API) genBasicToWMSV2PreItemDefLines(pbPkg *Package, packageMap map[string]*Package) (bool, []string) {
	module := api.Pkg.name
	isDefineJsErr := false
	params := []string{}
	for _, field := range api.ReqFields {
		if field.isContext() {
			continue
		}

		if field.isUpdateMap() {
			var lines []string
			lines = api.convertToUpdateMapLine(field)
			params = append(params, lines...)
			continue
		}

		if strings.Contains(toPbType(field.Type, packageMap), "Item") && field.Type != "*paginator.PageIn" {
			lines := []string{}
			initLines := field.toDefBasicItemOrItemsWithoutInit(module)
			lines = append(lines, initLines...)

			upAlias := upFirstChar(field.formatFieldAlias())
			//兼容MsizetypeCreateTaskSizeType
			if field.Alias == "size" {
				upAlias = "Item"
			}
			if field.Alias == "entity" {
				upAlias = "Entity"
			}
			lines = append(lines, fmt.Sprintf("if req.%s != nil {", upAlias))
			origItem := field.toDefBasicItemOrItems(module)
			lines = append(lines, origItem...)
			errMsg := "\t\tif jsErr := copier.Copy(req.%s, %s); jsErr != nil {\n\t\t\treturn nil, wmserror.NewError(constant.ErrJsonDecodeFail, jsErr.Error())\n\t\t}"
			lines = append(lines, fmt.Sprintf(errMsg, upAlias, field.formatFieldAlias()))

			lines = append(lines, "}")

			//lines = append(lines, api.viewHandlerErr())
			params = append(params, lines...)
		}

		//*paginator.PageIn
		if field.isPageInItem() {
			lines := field.convertPbToBasic(module)
			params = append(params, lines...)
		}

		if isNormalType(field.Type) {
			var item string
			//if field.Alias == "whsID" {
			//	item = fmt.Sprintf("var \t%s =req.GetWhsId()", field.aliasDef())
			//} else {

			pbType := api.parsePbFieldType(pbPkg, field)
			item = fmt.Sprintf("var \t%s =req.Get%s()", field.aliasDef(), pbType)
			//}
			params = append(params, item)
		}

		if strings.Contains(field.Type, "constant.") {
			var item string
			if strings.Contains(field.Type, "[]") {
				params = append(params, "%s:=req.Get%s")
				item = fmt.Sprintf("var \t%s = %s", field.aliasDef(), upFirstChar(field.Alias))
			} else {
				item = fmt.Sprintf("var \t%s =req.Get%s()", field.Alias, upFirstChar(field.Alias))
			}
			params = append(params, item)

		}

	}
	return isDefineJsErr, params
}

func (api *API) genWmsV2ToBasicPreItemDefLines(packageMap map[string]*Package) (bool, []string) {
	module := api.Pkg.name
	isDefineJsErr := false
	params := []string{}
	for _, field := range api.ReqFields {
		if field.isContext() {
			continue
		}

		if field.isUpdateMap() {
			var lines []string
			lines = api.convertToMapUpdateItemsLine(field)
			params = append(params, lines...)
			continue
		}

		if strings.Contains(toPbType(field.Type, packageMap), "Item") && field.Type != "*paginator.PageIn" {
			lines := field.toDefItemOrItems(module)

			errLines := field.genDealCopyJsErrLines(&isDefineJsErr, *api)
			lines = append(lines, errLines...)
			params = append(params, lines...)
		}

		//兼容 constant枚举值
		//sizeTypeList []constant.TaskSizeType
		if strings.Contains(field.Type, "[]") && strings.Contains(field.Type, "constant.") {
			lines := field.toDefItemOrItems(module)

			errLines := field.genDealCopyJsErrLines(&isDefineJsErr, *api)
			lines = append(lines, errLines...)
			params = append(params, lines...)
		}

		//*paginator.PageIn
		if field.isPageInItem() {
			lines := field.convertPageInAssignLines(module)
			params = append(params, lines...)
		}

	}
	return isDefineJsErr, params
}

func (api *API) convertToMapUpdateItemsLine(field *ReqField) []string {
	module := api.Pkg.name
	var params []string
	//if module != "msizetype" {
	retItemVars := api.apiRets()
	params = append(params, fmt.Sprintf("mapItems,err := convertToMapUpdateItems(%s)", field.Alias))

	params = append(params, "if err != nil {")
	if len(retItemVars) > 1 {
		errMsg := "\t\treturn  %s, wmserror.NewError(constant.ErrBadRequest, \"update map convert to item list err:%v\", err.Error())"
		params = append(params, fmt.Sprintf(errMsg, strings.Join(retItemVars[0:len(retItemVars)-1], ","), ""))
	} else {
		params = append(params, "\t\treturn  wmserror.NewError(constant.ErrBadRequest, \"update map convert to item list err:%v\", err.Error())")
	}
	params = append(params, "}")
	params = append(params, fmt.Sprintf("mapItemLists := []*pb%s.MapItem{}", module))
	params = append(params, "cpErr := copier.Copy(mapItems, &mapItemLists)")
	params = append(params, "if cpErr != nil {")
	if len(retItemVars) > 1 {
		errMsg := "\t\treturn  %s, wmserror.NewError(constant.ErrBadRequest, \"update map convert to item list err:%v\", cpErr.Error())"
		params = append(params, fmt.Sprintf(errMsg, strings.Join(retItemVars[0:len(retItemVars)-1], ","), ""))
	} else {
		params = append(params, "\t\treturn  wmserror.NewError(constant.ErrBadRequest, \"update map convert to item list err:%v\", cpErr.Error())")
	}

	params = append(params, "}")
	//} else {
	//
	//	retItemVars := api.apiRets()
	//	params = append(params, fmt.Sprintf("mapItemLists,err := convertToMapUpdateItems(%s)", field.Alias))
	//
	//	params = append(params, "if err != nil {")
	//	if len(retItemVars) > 1 {
	//		errMsg := "\t\treturn  %s, wmserror.NewError(constant.ErrBadRequest, \"update map convert to item list err:%v\", err.Error())"
	//		params = append(params, fmt.Sprintf(errMsg, strings.Join(retItemVars[0:len(retItemVars)-1], ","), ""))
	//	} else {
	//		params = append(params, "\t\treturn  wmserror.NewError(constant.ErrBadRequest, \"update map convert to item list err:%v\", err.Error())")
	//	}
	//	params = append(params, "}")
	//}
	return params
}

func (api *API) convertToUpdateMapLine(field *ReqField) []string {
	var params []string
	//兼容非updateMap
	params = append(params, fmt.Sprintf("%s,err := pbconvert.ConvertUpdateMaps(req.Get%s())", field.Alias, upFirstChar(field.Alias)))
	params = append(params, api.viewHandlerErr())
	api.genBasicV2Err = true
	return params
}

func (api *API) apiPbReqType() string {
	module := api.Pkg.name
	return fmt.Sprintf("pb%s.%sRequest", module, api.Method)
}
func (api *API) apiPbRespType() string {
	module := api.Pkg.name
	return fmt.Sprintf("pb%s.%sResponse", module, api.Method)
}

func (api *API) endpointEnum() string {
	endPointEnum := upFirstChar(api.Pkg.name) + api.Method
	return endPointEnum
}

func dealCopyErrLines(retItemVars []string) []string {
	var params []string
	params = append(params, "if jsErr != nil {")
	if len(retItemVars) > 1 {
		errMsg := "\t\treturn  %s, wmserror.NewError(constant.ErrBadRequest, \"json convert err:%v\", jsErr.Error())"
		params = append(params, fmt.Sprintf(errMsg, strings.Join(retItemVars[0:len(retItemVars)-1], ","), ""))

	} else {
		params = append(params, "\t\treturn  wmserror.NewError(constant.ErrBadRequest, \"json convert err:%v\", jsErr.Error())")
	}
	return params
}

func isNormalType(fieldTypeStr string) bool {
	normalTypes := []string{
		"int64",
		"string",
		"[]string",
		"[]int64",
	}
	for _, normalType := range normalTypes {
		if normalType == fieldTypeStr {
			return true
		}
	}
	return false
}

func (api *API) parsePbType(pbPkg *Package, pbReqType string, itemTypeMap map[string]map[string]*Field) {
	if pbPkg != nil {
		pbItemType, err := pbPkg.FindType(pbReqType)
		if err != nil {
			println(err.Error())
		}
		keyToMap := map[string]*Field{}
		if objType, ok := pbItemType.def.(*StructType); ok {
			for _, field := range objType.fields {
				keyToMap[strings.ToLower(field.name)] = field
			}
		}
		itemTypeMap[pbReqType] = keyToMap
	}
}

// eg [ret1,ret2,err]
func (api *API) apiRets() []string {
	rets := []string{}
	for i, ret := range api.Resp {
		v := fmt.Sprintf("ret%d", i+1)
		if ret == "*wmserror.WMSError" {
			v = "err"
		}
		rets = append(rets, v)
	}
	return rets
}

func (api *API) apiPbRets() []string {
	rets := []string{}
	for i, ret := range api.Resp {
		v := fmt.Sprintf("ret%d", i+1)
		v = convertToPbType(ret, v)
		if ret == "*wmserror.WMSError" {
			v = "err"
		}
		rets = append(rets, v)
	}
	return rets
}

// eg [
//	 "var ret1 int64",
//	 "var err *wmserr.err",
//]
func (api *API) apiRetDefs() []string {
	rets := []string{}
	for i, ret := range api.Resp {
		v := fmt.Sprintf("var %s  %s", fmt.Sprintf("ret%d", i+1), ret)
		if ret == "*wmserror.WMSError" {
			v = "var err *wmserror.WMSError"
		} else {
			if !isNormalType(ret) {
				if isSturctItems(ret) {
					v = fmt.Sprintf("var %s = %s{}", fmt.Sprintf("ret%d", i+1), ret)
				} else {
					ret = strings.ReplaceAll(ret, "*", "&")
					v = fmt.Sprintf("var %s = %s{}", fmt.Sprintf("ret%d", i+1), ret)
				}
			}
		}

		rets = append(rets, v)
	}
	return rets
}

func (api *API) proxyFuncBody2() string {
	var bodyStr []string
	bodyStr = append(bodyStr, api.FuncSignStr+"{")

	//var ret1 []*entity.CellSizeType
	//var ret2 int64
	//var ret3 *wmserror.WMSError
	for i, ret := range api.Resp {
		v := fmt.Sprintf("var %s %s", fmt.Sprintf("ret%d", i), ret)
		bodyStr = append(bodyStr, v)
	}

	//
	//originHandler := func(ctx context.Context) {
	//	ret1, ret2, ret3 = c.origin.SearchCellSizeList(ctx, whsID)
	//}
	retParams := []string{}
	for i := range api.Resp {
		retParams = append(retParams, fmt.Sprintf("ret%d ", i))
	}
	rets := strings.Join(retParams, ", ")

	bodyStr = append(bodyStr, "\toriginHandler := func(ctx context.Context) {")
	params := []string{}
	for _, field := range api.ReqFields {
		params = append(params, field.Alias)
	}
	paramsStr := strings.Join(params, ", ")

	callOriginal := fmt.Sprintf("= %s.%s.%s(%s)", api.ReceiverAlias, lowerFirstChar(api.ReceiverName), api.Method, paramsStr)
	bodyStr = append(bodyStr, rets+callOriginal)
	bodyStr = append(bodyStr, "\t}")

	bodyStr = append(bodyStr, "\tproxyHandler := func(ctx context.Context) *wmserror.WMSError{")
	proxyParams := []string{}
	for _, field := range api.ReqFields {
		if api.isNeedRedefineStruct(field) {
			copyReqs := []string{}

			reqStr := fmt.Sprintf("%sReq", field.Alias)
			//req := &wmsbasic.SearchCellSizeConditionItem{}
			originType := field.Type
			reqItemType := field.Type
			if strings.Contains(reqItemType, "*") && !strings.Contains(reqItemType, "[") {
				reqItemType = strings.Split(reqItemType, "*")[1]
			}
			if isSturctItems(originType) {
				fType := strings.ReplaceAll(originType, "[]*", "")
				copyReqs = append(copyReqs, fmt.Sprintf("%s := []*wmsbasic.%sItem{}", reqStr, fType))
			} else {
				copyReqs = append(copyReqs, fmt.Sprintf("%s := &wmsbasic.%sItem{}", reqStr, reqItemType))
			}

			//ctErr := copier.Copy(condition, &req)
			//todo 是否是指针
			copyReqs = append(copyReqs, fmt.Sprintf("ctErr := copier.Copy(%s, %s)", field.Alias, reqStr))
			//if ctErr != nil {
			//	return wmserror.NewError(constant.ErrJsonDecodeFail, ctErr.Error())
			//}
			copyReqs = append(copyReqs, "if ctErr != nil {")
			copyReqs = append(copyReqs, "return wmserror.NewError(constant.ErrJsonDecodeFail, ctErr.Error())")
			copyReqs = append(copyReqs, "}")

			bodyStr = append(bodyStr, strings.Join(copyReqs, "\n"))
			proxyParams = append(proxyParams, reqStr)
		} else {
			proxyParams = append(proxyParams, field.Alias)
		}
	}
	proxyParamsStr := strings.Join(proxyParams, ", ")

	proxyCallOriginal := fmt.Sprintf("= %s.%sProxyAPI.%s(%s)", api.ReceiverAlias, lowerFirstChar(api.ReceiverName), api.Method, proxyParamsStr)
	bodyStr = append(bodyStr, rets+proxyCallOriginal)
	bodyStr = append(bodyStr, fmt.Sprintf("return %s", retParams[len(retParams)-1]))
	bodyStr = append(bodyStr, "\t}")

	bodyStr = append(bodyStr, fmt.Sprintf("endPoint := \"%s\"", api.Method))
	if api.genBasicAPIMethod() == "GET" {
		bodyStr = append(bodyStr, "getBasicHandler()(ctx, endPoint, originHandler, proxyHandler, apiIdempotent)")
	} else {
		bodyStr = append(bodyStr, "getBasicHandler()(ctx, endPoint, originHandler, proxyHandler)")
	}
	bodyStr = append(bodyStr, "return "+rets)
	bodyStr = append(bodyStr, "}")

	return strings.Join(bodyStr, "\n")
}
func (api *API) proxyPbAPIReq() string {
	basicAPI := &BASICAPI{
		Package:     "",
		Req:         nil,
		ReqFields:   nil,
		RespTypeStr: nil,
		Pkg:         nil,
	}

	basicAPI.Method = api.genBasicAPIMethod()
	basicAPI.Path = "openapi/basic/" + api.Path + "/" + api.Method
	var reqFieldStr []string
	reqFieldStr = append(reqFieldStr, fmt.Sprintf("type %s%sReq struct{", upFirstChar(api.Package), api.Method))

	innerStructset := hashset.New()
	for _, field := range api.ReqFields {
		fieldParam := field.Alias
		fieldParamDef := upFirstChar(fieldParam)
		fieldType := field.Type
		if fieldType == "context.Context" {
			continue
		}

		//当前包下的struct
		//if !strings.Contains(fieldType, ".") &&
		//	fieldType != "string" &&
		//	fieldType != "int64" &&
		//	fieldType != "[]string" &&
		//	fieldType != "[]int64" {
		if api.isNeedRedefineStruct(field) {

			innerStructset.Add(strings.ReplaceAll(fieldType, "*", ""))
			reqFieldStr = append(reqFieldStr, fmt.Sprintf("\t%s %sItem `json:\"%s,omitempty\"`", fieldParamDef, fieldType, ToSnakeCase(fieldParamDef)))
		} else {
			reqFieldStr = append(reqFieldStr, fmt.Sprintf("\t%s %s `json:\"%s,omitempty\"`", fieldParamDef, fieldType, ToSnakeCase(fieldParamDef)))
		}
	}

	reqFieldStr = append(reqFieldStr, "}")
	for _, i := range innerStructset.Values() {
		fieldType := i.(string)
		depStructFieldType := api.genInnerPkgStructDef(fieldType)

		reqFieldStr = append(reqFieldStr, depStructFieldType)
	}

	reqDef := strings.Join(reqFieldStr, "\n")
	ret := reqDef
	return ret

}

func (api *API) proxyPbAPI() *BASICAPI {
	basicAPI := &BASICAPI{
		Package:     "",
		Req:         nil,
		ReqFields:   nil,
		RespTypeStr: nil,
		Pkg:         nil,
		api:         *api,
	}

	basicAPI.Package = api.Package
	basicAPI.Method = api.genBasicAPIMethod()
	basicAPI.Path = "openapi/basic/" + api.Path + "/" + api.Method
	basicAPI.ReqFields = api.ReqFields
	basicAPI.RespTypeStr = api.Resp
	return basicAPI

}

func (api *API) proxyProxyAPIReqItem() []string {
	basicAPI := &BASICAPI{}

	basicAPI.Path = "openapi/basic/" + api.Path + "/" + api.Method
	var reqFieldStr []string
	reqFieldStr = append(reqFieldStr, fmt.Sprintf("type %s%sReq struct{", upFirstChar(api.Package), api.Method))

	innerStructset := hashset.New()
	for _, field := range api.ReqFields {
		fieldParam := field.Alias
		fieldParamDef := upFirstChar(fieldParam)
		fieldType := field.Type
		if fieldType == "context.Context" {
			continue
		}

		//当前包下的struct
		//if !strings.Contains(fieldType, ".") &&
		//	fieldType != "string" &&
		//	fieldType != "int64" &&
		//	fieldType != "[]string" &&
		//	fieldType != "[]int64" {
		if api.isNeedRedefineStruct(field) {

			innerStructset.Add(strings.ReplaceAll(fieldType, "*", ""))
			reqFieldStr = append(reqFieldStr, fmt.Sprintf("\t%s %sItem `json:\"%s,omitempty\"`", fieldParamDef, fieldType, ToSnakeCase(fieldParamDef)))
		} else {
			reqFieldStr = append(reqFieldStr, fmt.Sprintf("\t%s %s `json:\"%s,omitempty\"`", fieldParamDef, fieldType, ToSnakeCase(fieldParamDef)))
		}
	}

	reqFieldStr = append(reqFieldStr, "}")
	var itemFields []string
	for _, i := range innerStructset.Values() {
		fieldType := i.(string)
		depStructFieldType := api.genInnerPkgStructDef(fieldType)

		itemFields = append(itemFields, depStructFieldType)
	}

	return itemFields

}

func (api *API) BasicAPIInterfaceSignWithComment() string {
	//prefix := "// proxy 原来 msku.SKUManager GetSkuSetForHighValueByWhsID 的请求\n "
	prefix := fmt.Sprintf("// %s \n// proxy 原来 %s.%s %s 的请求\n ", api.Method, api.Package, api.ReceiverName, api.Method)
	//println(prefix)
	sign := api.proxyBasicSign()
	return prefix + sign
}

func (api *API) proxyBasicSign() string {
	sign := fmt.Sprintf("%s(%s) %s", api.Method, api.methodReqSign(), api.methodReturnSign())
	return sign
}

func (api *API) methodReturnSign() string {
	var retParams []string
	for i := range api.Resp {
		retParams = append(retParams, fmt.Sprintf("%s ", api.Resp[i]))
	}
	var retSign = ""
	if len(retParams) > 1 {
		retSign = fmt.Sprintf("(%s)", strings.Join(retParams, ", "))
	} else {
		retSign = retParams[0]
	}
	return retSign
}
func (api *API) genInnerDefPkgStructs() []string {
	innerStructset := hashset.New()
	for _, field := range api.ReqFields {
		fieldType := field.Type
		if fieldType == "context.Context" {
			continue
		}

		//当前包下的struct
		if !strings.Contains(fieldType, ".") && fieldType != "string" && fieldType != "int64" {
			item := strings.ReplaceAll(fieldType, "*", "")
			item = strings.ReplaceAll(item, "[]", "")
			innerStructset.Add(item)
		}
	}
	var items []string
	for _, i := range innerStructset.Values() {
		fieldType := i.(string)
		items = append(items, fieldType)
	}
	return items
}
func (api *API) genOuterDefPkgStructs() []string {
	outStructset := hashset.New()
	for _, field := range api.ReqFields {
		fieldType := field.Type
		if fieldType == "context.Context" {
			continue
		}

		//当前包下的struct
		if strings.Contains(fieldType, ".") {
			outStructset.Add(fieldType)
		}
	}
	for _, field := range api.Resp {

		//当前包下的struct
		if strings.Contains(field, ".") {
			outStructset.Add(field)
		}
	}
	var items []string
	for _, i := range outStructset.Values() {
		fieldType := i.(string)
		items = append(items, fieldType)
	}
	return items
}
func (api *API) genInnerPkgStructDef(fieldType string) string {
	//兼容[]*sss
	fieldType = strings.ReplaceAll(fieldType, "[]", "")
	var def = []string{}
	defHead := fmt.Sprintf("type %sItem struct{", fieldType)
	def = append(def, defHead)
	for _, file := range api.Pkg.files {
		t, err := file.FindType(fieldType)
		if err != nil && strings.Contains(err.Error(), "is not found") {
			continue
		}
		//for _, field := range t.def.(*StructType).Fields() {
		//	println(field.Definition().String())
		//}
		originDef := t.Definition().String
		withoutHeadDef := strings.ReplaceAll(originDef(), "struct {", "")
		def = append(def, withoutHeadDef)
		//println(t)
	}
	return strings.Join(def, "\n")
}

func (api *API) methodReqSign() string {
	var params []string
	for _, field := range api.ReqFields {
		curFieldType := field.Type
		isNeedRedefineStruct := api.isNeedRedefineStruct(field)
		if isNeedRedefineStruct {
			curFieldType = curFieldType + "Item"
		}
		//兼容type []HighValueCategoryUpdateConditionItem
		//curFieldType = strings.ReplaceAll(curFieldType, "[]", "")
		params = append(params, fmt.Sprintf("%s %s", field.Alias, curFieldType))
	}
	return strings.Join(params, ",")
}

func (api *API) isNeedRedefineStruct(field *ReqField) bool {
	fType := strings.ReplaceAll(field.Type, "[]", "")

	isNeedRedefineStruct := !strings.Contains(fType, ".") &&
		!strings.Contains(field.Type, "map[string]") &&
		field.Type != "context.Context" &&
		field.Type != "string" &&
		field.Type != "int64" &&
		field.Type != "[]string" &&
		field.Type != "[]int64"
	return isNeedRedefineStruct
}

func (api *API) genBasicAPIMethod() string {
	//全是POST ，但是通过业务层去控制，是不是幂等操作

	return "POST"
	//if len(api.Resp) == 1 {
	//	return "POST"
	//}
	//return "GET"
}

func (api *API) pbReqType() string {
	return fmt.Sprintf("%sRequest", api.Method)

}

// 解析pb对应的字段map，可以获取到对应的json tag
func (api *API) parsePbReqType(pbPkg *Package) map[string]*Field {
	pbReqType := api.pbReqType()
	itemTypeMap := map[string]map[string]*Field{}
	api.parsePbType(pbPkg, pbReqType, itemTypeMap)
	reqPbTypesMap := itemTypeMap[pbReqType]

	return reqPbTypesMap
}

var matchFirstCap = regexp.MustCompile("(.)([A-Z][a-z]+)")
var matchAllCap = regexp.MustCompile("([a-z0-9])([A-Z])")

func ToSnakeCase(str string) string {
	snake := matchFirstCap.ReplaceAllString(str, "${1}_${2}")
	snake = matchAllCap.ReplaceAllString(snake, "${1}_${2}")
	return strings.ToLower(snake)
}

func upFirstChar(fieldParam string) string {
	r := []rune(fieldParam)
	return string(append([]rune{unicode.ToUpper(r[0])}, r[1:]...))
}

func lowerFirstChar(fieldParam string) string {
	r := []rune(fieldParam)
	return string(append([]rune{unicode.ToLower(r[0])}, r[1:]...))
}

type DTO struct {
	Val string
}

func ToCamelCase() string {
	result1 := stringy.New("whs_id").SnakeCase()
	return result1.CamelCase()

}

func genReqAndResp(f *Function) *API {
	api := &API{
		Path:    f.pkg.path,
		Package: f.pkg.name,
		Method:  "",
		Req:     map[string]string{},
		Resp:    nil,
	}
	for _, parameter := range f.Func().parameters {
		val := parameter.Definition().String()
		pName := parameter.name
		//println("		param:", pName, val)
		api.Req[pName] = val
		api.ReqFields = append(api.ReqFields, &ReqField{
			Alias: pName,
			Type:  val,
		})
	}

	for _, result := range f.Func().results {
		val := result.def.String()
		api.Resp = append(api.Resp, val)
		//println("		ret:", val)
	}
	api.Method = f.name
	api.Func = f.Func()
	return api
}

func ToJSON(data interface{}) string {
	b, err := json.Marshal(data)
	if err != nil {
		println(err.Error())
	}
	return string(b)
}
func ToPrettyJSON(data interface{}) string {
	b, err := json.MarshalIndent(data, "", "    ")
	if err != nil {
		println(err.Error())
	}
	return string(b)
}

func TestName(t *testing.T) {
	println(color.InBold("This is bold"))
	println(color.InUnderline("This is underlined"))
	println(color.InBlack("This is black"))
	println(color.InRed("This is red"))
	println(color.InGreen("This is green"))
	println(color.InYellow("This is yellow"))
	println(color.InBlue("This is blue"))
	println(color.InPurple("This is purple"))
	println(color.InCyan("This is cyan"))
	println(color.InGray("This is gray"))
	println(color.InWhite("This is white"))
}
func isExported(p string) bool {
	return p[0] <= 'Z' && p[0] >= 'A'

}

func TestName2(t *testing.T) {
	var aa = []string{}
	println(len(add11(aa)))
	println(len(add11(aa)))
	println(len(add11(aa)))
	println(len(add11(aa)))
	println(len(add11(aa)))
	println(len(add11(aa)))
}

func add11(aa []string) []string {
	aa = append(aa, "11")
	return aa
}

func TestName1(t *testing.T) {
	result := stringy.New("whsID").CamelCase()
	fmt.Println(result) // HelloManHowAreYou
	result1 := stringy.New("whs_id").SnakeCase()
	fmt.Println(result1.CamelCase()) // HelloManHowAreYou

}
