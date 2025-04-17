// Copyright (c) seasonjs. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

package main

import (
	"context"

	"github.com/seasonjs/hf-hub/api"
)

func main() {
	hapi, err := api.NewApi()
	if err != nil {
		print(err.Error())
		return
	}

	ctx := context.Background()
	modelPath, err := hapi.Model("bert-base-uncased").Get(ctx, "config.json")
	if err != nil {
		print(err.Error())
		return
	}

	print(modelPath)
}
