package handlers

import (
	"context"

	introspectorv1 "github.com/arkade-os/introspector/api-spec/protobuf/gen/introspector/v1"
	"github.com/arkade-os/introspector/internal/application"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type handler struct {
	version string
	svc     application.Service
}

func New(version string, service application.Service) *handler {
	return &handler{version: version, svc: service}
}

func (h *handler) GetInfo(
	ctx context.Context, _ *introspectorv1.GetInfoRequest,
) (*introspectorv1.GetInfoResponse, error) {
	info, err := h.svc.GetInfo(ctx)
	if err != nil {
		return nil, err
	}

	return &introspectorv1.GetInfoResponse{
		SignerPubkey: info.SignerPublicKey,
		Version:      h.version,
	}, nil
}

func (h *handler) SubmitTx(
	ctx context.Context, req *introspectorv1.SubmitTxRequest,
) (*introspectorv1.SubmitTxResponse, error) {
	arkTx := req.GetArkTx()
	checkpoints := req.GetCheckpointTxs()

	if len(arkTx) <= 0 {
		return nil, status.Error(codes.InvalidArgument, "missing ark tx")
	}

	if len(checkpoints) <= 0 {
		return nil, status.Error(codes.InvalidArgument, "missing checkpoint txs")
	}

	offchainTx := application.OffchainTx{
		ArkTx:       arkTx,
		Checkpoints: checkpoints,
	}

	approvedTx, err := h.svc.SubmitTx(ctx, offchainTx)
	if err != nil {
		return nil, err
	}

	return &introspectorv1.SubmitTxResponse{
		SignedArkTx:         approvedTx.ArkTx,
		SignedCheckpointTxs: approvedTx.Checkpoints,
	}, nil
}
