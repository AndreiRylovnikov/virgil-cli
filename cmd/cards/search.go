/*
 * Copyright (C) 2015-2020 Virgil Security Inc.
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     (1) Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *
 *     (3) Neither the name of the copyright holder nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 */
package cards

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/urfave/cli/v2"
	"gopkg.in/virgil.v5/cryptoimpl"
	"gopkg.in/virgil.v5/sdk"

	"github.com/VirgilSecurity/virgil-cli/utils"
)

var (
	crypto      = cryptoimpl.NewVirgilCrypto()
	cardCrypto  = cryptoimpl.NewVirgilCardCrypto()
	tokenSigner = cryptoimpl.NewVirgilAccessTokenSigner()
)

func Search() *cli.Command {
	return &cli.Command{
		Name:      "search",
		ArgsUsage: "[identity]",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "c", Usage: "configuration file"},
		},
		Usage: "search cards by identity",
		Action: func(context *cli.Context) error {
			identity := utils.ReadParamOrDefaultOrFromConsole(context, "identity", "Enter card identity", "")
			cardVerifier, err := sdk.NewVirgilCardVerifier(cardCrypto, true, true)
			if err != nil {
				return err
			}

			configFileName := utils.ReadFlagOrDefault(context, "c", "")
			if configFileName == "" {
				return errors.New("configuration file isn't specified (use -c)")
			}

			data, err := ioutil.ReadFile(configFileName)
			if err != nil {
				return err
			}

			conf, err := utils.ParseAppConfig(data)
			if err != nil {
				return err
			}

			privateKey, err := crypto.ImportPrivateKey(conf.APIKey, "")
			if err != nil {
				return err
			}

			ttl := time.Minute

			jwtGenerator := sdk.NewJwtGenerator(privateKey, conf.APIKeyID, tokenSigner, conf.AppID, ttl)

			mgrParams := &sdk.CardManagerParams{
				Crypto:              cardCrypto,
				CardVerifier:        cardVerifier,
				AccessTokenProvider: sdk.NewGeneratorJwtProvider(jwtGenerator, nil, ""),
			}

			cardManager, err := sdk.NewCardManager(mgrParams)
			if err != nil {
				return err
			}

			cards, err := cardManager.SearchCards(identity)
			if err != nil {
				return err
			}

			if len(cards) == 0 {
				fmt.Println("there are no cards found for identity : " + identity)
				return nil
			}

			fmt.Printf("|%64s |%63s |%20s\n", " Card ID   ", "Public key   ", " created_at ")
			fmt.Printf("|%64s|%64s|%20s\n",
				"-----------------------------------------------------------------",
				"----------------------------------------------------------------",
				"---------------------------------------",
			)
			for _, c := range cards {
				pk, err := crypto.ExportPublicKey(c.PublicKey)
				if err != nil {
					return err
				}
				fmt.Printf("|%63s |%63s |%20s\n", c.Id, base64.StdEncoding.EncodeToString(pk), c.CreatedAt)
			}

			return nil
		},
	}
}
